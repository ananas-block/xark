//! `#[circuit]` — declare a circuit entry with **native** input types and
//! generate a native-typed input struct for its `xark_prover` tests.
//!
//! ```ignore
//! #[circuit]
//! pub fn sha256(msg: Private<[u8; 3]>, digest: Public<Hash>) {
//!     require_eq(xark_sha256::sha256(msg), digest);
//! }
//! ```
//!
//! The macro: (1) rewrites the signature into the Field-backed types the compiler
//! lowers (`[u8; N]` stays real bytes, range-checked by the compiler and converted to
//! `[Field; N]` at the top of the body; a `NativeInput` gadget → its native form), emitting the body verbatim; (2)
//! generates a native-typed `<Fn>Inputs` struct, named so parameters can't be
//! transposed; (3) implements `ProveInputs`, fanning each parameter out to its witness
//! leaves using the compiler's structural-flatten leaf names and decimal values; (4)
//! generates `<Fn>Inputs::schema()`, a JSON description of the inputs for client
//! codegen. Core stays gadget-agnostic — `Hash` packing lives in `xark-hash`, not here.
//!
//! `#[derive(CircuitInput)]` — see [`derive_circuit_input`] — generates the
//! `Into<[Field; N]>` (and `to_fields`) whose flatten order mechanically matches the
//! compiler's structural-flatten order, plus the host-side leaves and schema.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DataStruct, DeriveInput, Expr, ExprLit, FnArg, GenericArgument, ItemFn, Lit,
    LitInt, LitStr, Pat, PathArguments, Type, parse_macro_input,
};

#[proc_macro_attribute]
pub fn circuit(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);
    match circuit_impl(&func) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// How a `#[circuit]` parameter fans out to witness leaves. The compiler names
/// leaves by structurally flattening the *circuit* type (`flatten_field_leaves`),
/// so this must reproduce those exact names and their values.
enum Fanout {
    /// A `Field` scalar: one leaf named exactly `name`.
    Scalar,
    /// A native `uN` scalar (width `N`): one leaf, range-checked by the compiler.
    Uint(u32),
    /// `[uN; LEN]` for `N > 8`: `LEN` leaves `name[i]`, each range-checked by the compiler.
    IntArray(usize, u32),
    /// `[u8; N]`: `N` byte leaves `name[0..N]`, range-checked by the compiler and
    /// converted to `[Field; N]` at the top of the body.
    ByteArray(usize),
    /// `[Field; N]` → `[Field; N]`: `N` field leaves `name[0..N]`, native form
    /// `[String; N]` decimals (a field value per element — hashes, limbs, …).
    FieldArray(usize),
    /// A transparent gadget type (`Fq`, `Point`) implementing
    /// [`xark_prover::NativeInput`]: fan-out delegates to its `leaves`, native
    /// struct field is its `NativeInput::Native` associated type.
    Native,
}

/// One resolved entry parameter.
struct CircuitParam {
    /// Struct field name *and* leaf-name root.
    name: syn::Ident,
    /// `Private` / `Public`, as the author wrote it.
    wrapper: syn::Ident,
    /// Generated `<Fn>Inputs` field type — the **native** type (`[u8; 32]`, `String`).
    native_ty: TokenStream2,
    /// Compiler-visible inner type (`::xark::Field`, `[::xark::Field; N]`, a gadget type).
    circuit_ty: TokenStream2,
    fanout: Fanout,
}

/// Rewrite a `#[circuit]` entry: map native parameter types to the Field-backed
/// circuit types the compiler accepts, and emit a native-typed `<Fn>Inputs` struct
/// whose `ProveInputs` fans each parameter out to its witness leaves for `check`.
fn circuit_impl(func: &ItemFn) -> syn::Result<TokenStream2> {
    let params = func
        .sig
        .inputs
        .iter()
        .map(resolve_param)
        .collect::<syn::Result<Vec<_>>>()?;

    let attrs = &func.attrs;
    let vis = &func.vis;
    let fn_ident = &func.sig.ident;
    let stmts = &func.block.stmts;
    let sig_params: Vec<TokenStream2> = params
        .iter()
        .map(|p| {
            let (name, wrapper, cty) = (&p.name, &p.wrapper, &p.circuit_ty);
            quote! { #name: #wrapper<#cty> }
        })
        .collect();
    // The real `Field` circuit body (the one `__xark_main` binds the inputs for and
    // calls), emitted under a hidden name so it is **never cfg-gated** — it compiles in
    // every build; `cargo`/host builds just carry it as present-but-unused code, which also
    // keeps the circuit's `use`s live (no separate `__circuit_def` shim needed).
    //
    // Keeping it un-gated is what stops rust-analyzer greying the body you wrote: every
    // item the macro emits at the `#[circuit]` span is active under the editor's cfg, so
    // none of them mark the span inactive. The user's `fn` name is reused below for the
    // native-typed validator, which is what host/test code calls — no collision, since
    // the entry carries a distinct hidden name.
    let entry_ident = format_ident!("__{}_entry", fn_ident);
    // A `[u8; N]` parameter enters the circuit as real `u8`s, so the compiler range-checks
    // each byte on entry and records the true type in `schema.json`; the body then sees
    // it as `[Field; N]` (what the byte gadgets take). The conversion is free, and a
    // gadget's own `to_bits::<8>` of a byte hits the bit cache the entry check filled.
    let byte_convs = params.iter().filter_map(|p| match p.fanout {
        Fanout::ByteArray(n) => {
            let name = &p.name;
            Some(quote! {
                let #name: [::xark::Field; #n] = ::xark::bytes_to_fields(#name);
            })
        }
        _ => None,
    });
    let entry = quote! {
        #[doc(hidden)]
        #(#attrs)*
        #vis fn #entry_ident(#(#sig_params),*) {
            #(#byte_convs)*
            #(#stmts)*
        }
    };

    // Stable-frontend entry (`--cfg xark` on `wasm32`): bind every input leaf through
    // the compiler's input import — in parameter order, each in structural-flatten
    // order — then run the body. The compiler executes this export.
    let wasm_binds = params.iter().map(|p| {
        let (name, cty) = (&p.name, &p.circuit_ty);
        let name_lit = LitStr::new(&name.to_string(), name.span());
        let public = p.wrapper == "Public";
        quote! {
            let #name: #cty = ::xark::wasm::input(&mut __name, #name_lit, #public);
        }
    });
    let wasm_args = params.iter().map(|p| &p.name);
    let entry_name = fn_ident.to_string();
    let entry_len = entry_name.len();
    let entry_bytes = syn::LitByteStr::new(entry_name.as_bytes(), fn_ident.span());
    let wasm_main = quote! {
        // The circuit's name, for the compiler (a custom wasm section).
        #[cfg(all(xark, target_arch = "wasm32"))]
        #[unsafe(link_section = "xark.entry")]
        #[used]
        static __XARK_ENTRY: [u8; #entry_len] = *#entry_bytes;

        #[cfg(all(xark, target_arch = "wasm32"))]
        #[doc(hidden)]
        #[unsafe(no_mangle)]
        pub extern "C" fn __xark_main() {
            let mut __name = ::xark::wasm::NameBuf::new();
            #(#wasm_binds)*
            ::xark::wasm::inputs_done();
            #entry_ident(#(#wasm_args),*);
        }
    };

    let struct_name = format_ident!("{}Inputs", to_pascal(&fn_ident.to_string()));
    let field_defs = params.iter().map(|p| {
        let (name, nty) = (&p.name, &p.native_ty);
        quote! { pub #name: #nty }
    });
    let fanouts = params.iter().map(fanout_code);

    let fn_name_lit = LitStr::new(&fn_ident.to_string(), fn_ident.span());
    // The native-typed validator replacing the entry `fn` in test/host builds: same
    // name, the entry's native parameter types in order, returning the check result.
    let host_params = params.iter().map(|p| {
        let (name, nty) = (&p.name, &p.native_ty);
        quote! { #name: #nty }
    });
    let host_ctor = params.iter().map(|p| &p.name);

    // A machine-readable description of the circuit's inputs: each input's name,
    // visibility, and type, with every `#[derive(CircuitInput)]` struct it reaches
    // described once under `types`. Built at run time from the types themselves (a
    // struct's fields live in another macro expansion), so it needs only `cargo build`,
    // no `xark setup` and no proof. Client codegen (TypeScript types, …) consumes it.
    let schema_inputs = params.iter().map(|p| {
        let name = p.name.to_string();
        let vis = if p.wrapper == "Public" {
            "public"
        } else {
            "private"
        };
        let ty = match &p.fanout {
            Fanout::Scalar => quote! { ::std::string::String::from("\"field\"") },
            Fanout::Uint(w) => {
                let j = format!("{{\"uint\":{w}}}");
                quote! { ::std::string::String::from(#j) }
            }
            Fanout::ByteArray(n) => {
                let j = format!("{{\"array\":{{\"of\":{{\"uint\":8}},\"len\":{n}}}}}");
                quote! { ::std::string::String::from(#j) }
            }
            Fanout::FieldArray(n) => {
                let j = format!("{{\"array\":{{\"of\":\"field\",\"len\":{n}}}}}");
                quote! { ::std::string::String::from(#j) }
            }
            Fanout::IntArray(n, w) => {
                let j = format!("{{\"array\":{{\"of\":{{\"uint\":{w}}},\"len\":{n}}}}}");
                quote! { ::std::string::String::from(#j) }
            }
            Fanout::Native => {
                let cty = &p.circuit_ty;
                quote! { <#cty as ::xark_prover::NativeInput>::schema(&mut __defs) }
            }
        };
        quote! {
            ::std::format!(
                "{{\"name\":\"{}\",\"visibility\":\"{}\",\"type\":{}}}",
                #name, #vis, #ty
            )
        }
    });

    Ok(quote! {
        #entry

        #wasm_main

        /// Native-typed validator for this circuit, carrying the name you gave the `#[circuit]`
        /// fn. In host/test builds this *is* `<fn>` (the real `Field` body lives under a hidden
        /// name): it takes the entry's native inputs, loads the built circuit from
        /// `target/xark/<name>/`, and returns `Ok(())` if they satisfy it. Dropped from the
        /// `xark` build, where the hidden entry is what gets compiled to a circuit.
        #[cfg(not(xark))]
        #(#attrs)*
        #vis fn #fn_ident(#(#host_params),*) -> ::core::result::Result<(), ::xark_prover::ProveError> {
            ::xark_prover::circuit(#fn_name_lit).check(#struct_name { #(#host_ctor),* })
        }

        /// Typed inputs for this circuit (generated by `#[circuit]`), one field per
        /// entry parameter with its **native** type. For a custom artifact location:
        /// `xark_prover::circuit_at(dir).check(<Fn>Inputs { .. })` — or `.prove(..)`.
        #[cfg(not(xark))]
        #[derive(Clone, Debug)]
        pub struct #struct_name {
            #(#field_defs,)*
        }

        #[cfg(not(xark))]
        impl ::xark_prover::ProveInputs for #struct_name {
            fn into_inputs(self) -> ::std::vec::Vec<(::std::string::String, ::std::string::String)> {
                let mut out: ::std::vec::Vec<(::std::string::String, ::std::string::String)> =
                    ::std::vec::Vec::new();
                #(#fanouts)*
                out
            }
        }

        #[cfg(not(xark))]
        impl #struct_name {
            /// JSON description of this circuit's inputs, in declaration order (which is
            /// also public-input order for the `public` ones):
            ///
            /// ```text
            /// {"circuit": "<fn>",
            ///  "inputs": [{"name", "visibility": "public"|"private", "type"}, …],
            ///  "types": {"<Struct>": {"struct": [{"name", "type"}, …]}, …}}
            /// ```
            ///
            /// A `type` is `"field"`, `{"uint": N}`, `{"array": {"of": <type>, "len": N}}`, `{"ref": "<Struct>"}` (a
            /// `#[derive(CircuitInput)]` struct, described in `types`), or
            /// `{"opaque": "<rust path>"}` (a gadget type with its own encoding). Leaf
            /// names follow from it: `name.field`, `name[i]`. Generated by `#[circuit]`, so
            /// client codegen needs only `cargo build`: no `xark setup`, no proof.
            pub fn schema() -> ::std::string::String {
                let mut __defs: ::std::collections::BTreeMap<::std::string::String, ::std::string::String> =
                    ::std::collections::BTreeMap::new();
                let __inputs: ::std::vec::Vec<::std::string::String> = ::std::vec![#(#schema_inputs),*];
                let __types: ::std::vec::Vec<::std::string::String> = __defs
                    .iter()
                    .map(|(k, v)| ::std::format!("\"{}\":{}", k, v))
                    .collect();
                ::std::format!(
                    "{{\"circuit\":\"{}\",\"inputs\":[{}],\"types\":{{{}}}}}",
                    #fn_name_lit,
                    __inputs.join(","),
                    __types.join(","),
                )
            }
        }
    })
}

/// Resolve one entry parameter: a plain identifier wrapped in `Private<_>` /
/// `Public<_>`, whose inner native type maps to a supported circuit type.
fn resolve_param(arg: &FnArg) -> syn::Result<CircuitParam> {
    let pt = match arg {
        FnArg::Typed(pt) => pt,
        FnArg::Receiver(r) => {
            return Err(syn::Error::new_spanned(
                r,
                "#[circuit] cannot take a `self` parameter",
            ));
        }
    };
    let name = match &*pt.pat {
        Pat::Ident(pi) => pi.ident.clone(),
        other => {
            return Err(syn::Error::new_spanned(
                other,
                "#[circuit] parameters must be plain identifiers (no `_`, no patterns)",
            ));
        }
    };
    let (wrapper, inner) = unwrap_visibility(&pt.ty)?;
    let (native_ty, circuit_ty, fanout) = map_inner(&inner)?;
    Ok(CircuitParam {
        name,
        wrapper,
        native_ty,
        circuit_ty,
        fanout,
    })
}

/// Peel `Private<Inner>` / `Public<Inner>`, returning the wrapper ident and inner
/// type. A circuit input must declare visibility, so anything else is an error.
fn unwrap_visibility(ty: &Type) -> syn::Result<(syn::Ident, Type)> {
    if let Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && (seg.ident == "Private" || seg.ident == "Public")
        && let PathArguments::AngleBracketed(ab) = &seg.arguments
        && let Some(GenericArgument::Type(inner)) = ab.args.first()
    {
        return Ok((seg.ident.clone(), inner.clone()));
    }
    let t = quote::quote!(#ty).to_string().replace(' ', "");
    Err(syn::Error::new_spanned(
        ty,
        format!(
            "unsupported circuit parameter type `{t}`: #[circuit] parameters must be \
             wrapped in `Private<..>` or `Public<..>`\n\
             help: declare its visibility, e.g. `Private<{t}>` (a witness) or \
             `Public<{t}>` (a public input)"
        ),
    ))
}

/// Map a native inner type to `(native struct-field type, circuit inner type, fanout)`.
/// Supported: `Field`, `[u8; N]`, `[Field; N]`, or a type implementing `NativeInput`.
fn map_inner(inner: &Type) -> syn::Result<(TokenStream2, TokenStream2, Fanout)> {
    if let Type::Path(tp) = inner
        && tp.path.segments.last().is_some_and(|s| s.ident == "Field")
    {
        // A `Field` is a full field element (~254 bits, past `i128`), so the
        // struct takes it as a `String` (decimal or `0x`-hex), matching how the
        // CLI `--inputs` takes scalars. The circuit side keeps the type as written
        // (not `::xark::Field`), so the author's `use xark::Field` stays used.
        return Ok((quote! { String }, quote! { #inner }, Fanout::Scalar));
    }
    // Native unsigned integers are first-class circuit witnesses: the `<Fn>Inputs`
    // field takes the native `uN` (fits `u128`, so no `String` needed), the circuit
    // body sees the same `uN` (the compiler range-checks it `< 2^N` on entry and
    // lowers its comparisons), and it fans out to one decimal leaf. Must precede the
    // gadget-type fallback, else `u64` would be treated as a `NativeInput` type.
    if let Type::Path(tp) = inner
        && let Some(seg) = tp.path.segments.last()
        && matches!(
            seg.ident.to_string().as_str(),
            "u8" | "u16" | "u32" | "u64" | "u128"
        )
    {
        let w = uint_bits(&seg.ident.to_string()).expect("matched a uN above");
        return Ok((quote! { #inner }, quote! { #inner }, Fanout::Uint(w)));
    }
    if let Type::Array(arr) = inner
        && let Type::Path(elem) = &*arr.elem
    {
        if elem.path.segments.last().is_some_and(|s| s.ident == "u8") {
            let n = eval_usize_lit(&arr.len)?;
            return Ok((
                quote! { [u8; #n] },
                quote! { [u8; #n] },
                Fanout::ByteArray(n),
            ));
        }
        if elem
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "Field")
        {
            // A field-valued array (hash siblings, bignum limbs, …): native form
            // is `[String; N]` of decimals, the array analogue of `Field` → `String`.
            let n = eval_usize_lit(&arr.len)?;
            return Ok((
                quote! { [::std::string::String; #n] },
                quote! { #inner },
                Fanout::FieldArray(n),
            ));
        }
        // `[uN; LEN]` (wider than a byte): the circuit sees the same native array, and
        // the compiler range-checks each element on entry.
        if let Some(w) = elem
            .path
            .segments
            .last()
            .and_then(|s| uint_bits(&s.ident.to_string()))
        {
            let n = eval_usize_lit(&arr.len)?;
            return Ok((quote! { #inner }, quote! { #inner }, Fanout::IntArray(n, w)));
        }
    }
    // Fallback: any other named type is a transparent gadget type (`Fq`/`Point`)
    // implementing `xark_prover::NativeInput`. Its `Native` associated type is the
    // struct field, and its `leaves` produce the compiler's flatten names. A type
    // that doesn't impl the trait is a compile error at the delegation site.
    if let Type::Path(_) = inner {
        return Ok((
            quote! { <#inner as ::xark_prover::NativeInput>::Native },
            quote! { #inner },
            Fanout::Native,
        ));
    }
    Err(syn::Error::new_spanned(
        inner,
        "unsupported #[circuit] parameter type; supported: `Field`, `u8`..`u128`, \
         `[u8; N]`, `[uN; N]`, `[Field; N]`, a `#[derive(CircuitInput)]` struct, or a \
         gadget type implementing `NativeInput`",
    ))
}

/// The `ProveInputs` fan-out statements for one parameter: push `(leaf-name,
/// decimal-value)` pairs whose names match the compiler's structural-flatten
/// names for the circuit type, in flatten order.
fn fanout_code(p: &CircuitParam) -> TokenStream2 {
    let name = &p.name;
    let name_lit = LitStr::new(&name.to_string(), name.span());
    match p.fanout {
        Fanout::Scalar | Fanout::Uint(_) => quote! {
            out.push((
                ::std::string::String::from(#name_lit),
                ::std::string::ToString::to_string(&self.#name),
            ));
        },
        // Byte and field arrays fan out identically: leaf `name[i]` = the element
        // rendered as a decimal string.
        Fanout::ByteArray(n) | Fanout::FieldArray(n) | Fanout::IntArray(n, _) => quote! {
            {
                let mut __i = 0usize;
                while __i < #n {
                    out.push((
                        ::std::format!("{}[{}]", #name_lit, __i),
                        ::std::string::ToString::to_string(&self.#name[__i]),
                    ));
                    __i += 1;
                }
            }
        },
        // Transparent gadget type: delegate to `NativeInput::leaves`, which produces
        // the compiler's flatten names (`name.x.limbs[i]`, `name[i]`, …).
        Fanout::Native => {
            let ty = &p.circuit_ty;
            quote! {
                out.extend(
                    <#ty as ::xark_prover::NativeInput>::leaves(&self.#name, #name_lit),
                );
            }
        }
    }
}

/// Bit width of a native unsigned integer type name (`"u64"` → `64`).
fn uint_bits(ident: &str) -> Option<u32> {
    Some(match ident {
        "u8" => 8,
        "u16" => 16,
        "u32" => 32,
        "u64" => 64,
        "u128" => 128,
        _ => return None,
    })
}

/// Whether `ty` is a native unsigned integer, returning its width.
fn uint_type_bits(ty: &Type) -> Option<u32> {
    match ty {
        Type::Path(tp) if tp.qself.is_none() && tp.path.segments.len() == 1 => {
            uint_bits(&tp.path.segments[0].ident.to_string())
        }
        _ => None,
    }
}

/// `my_square` → `MySquare` (for the `<Name>Inputs` struct). Falls back to
/// `Circuit` for a degenerate all-separator name (e.g. `__`), so the struct is
/// never named just `Inputs`.
fn to_pascal(s: &str) -> String {
    let pascal: String = s
        .split('_')
        .filter(|seg| !seg.is_empty())
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect();
    if pascal.is_empty() {
        "Circuit".to_string()
    } else {
        pascal
    }
}

/// `#[derive(CircuitInput)]` — make a Field-composed struct usable as a typed
/// circuit input by generating its `From<Self> for [Field; N]`, **in the compiler's
/// structural-flatten order**: fields in declaration order, arrays in index order,
/// bottoming out at `Field`. The compiler flattens the input type the same way, so
/// leaf `k` of the produced array is always leaf `k` of the input — making
/// host↔circuit layout agreement a mechanical guarantee, not discipline.
///
/// ```ignore
/// #[derive(Clone, Copy, CircuitInput)]
/// struct Digest { bits: [[Field; 32]; 8] }   // ⇒ impl From<Digest> for [Field; 256]
/// ```
///
/// Supported field types: `Field`, native `u8`..`u128` (range-checked on entry, flattened
/// with `Field::from`), another `#[derive(CircuitInput)]` struct (flattened inline), and
/// fixed arrays of any of these with **integer-literal** lengths. Generic types are
/// rejected — the flattened length must be a compile-time constant; write the `From` by hand.
#[proc_macro_derive(CircuitInput)]
pub fn derive_circuit_input(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    match circuit_input_impl(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn circuit_input_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "#[derive(CircuitInput)] does not support generic types: the flattened length \
             must be a compile-time literal. Implement `From<Self> for [Field; N]` by hand.",
        ));
    }
    let data = match &input.data {
        Data::Struct(d) => d,
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "#[derive(CircuitInput)] only supports structs",
            ));
        }
    };

    // Per field: (flatten-name, accessor suffix, type).
    let fields: Vec<(String, TokenStream2, &Type)> = data
        .fields
        .iter()
        .enumerate()
        .map(|(i, f)| match &f.ident {
            Some(id) => (id.to_string(), quote! { #id }, &f.ty),
            None => {
                let idx = syn::Index::from(i);
                (i.to_string(), quote! { #idx }, &f.ty)
            }
        })
        .collect();

    // Leaf count as a const expression: a nested struct contributes its own
    // `FIELD_LEN`, so the total is only known to the type checker, not to this macro.
    let mut counts = Vec::new();
    let mut blocks = Vec::new();
    let mut self_blocks = Vec::new();
    for (_, acc, ty) in &fields {
        let (count, stmts) = walk_type(ty, &quote! { __v.#acc }, 0)?;
        counts.push(count);
        blocks.push(stmts);
        // The same structural flatten as the `From` impl, but reading through `&self`
        // (every leaf is `Copy`), so callers get the field array without consuming or
        // cloning. Powers the inherent `to_fields(&self)` below.
        let (_, stmts) = walk_type(ty, &quote! { self.#acc }, 0)?;
        self_blocks.push(stmts);
    }
    let n = quote! { (0usize #( + #counts )*) };

    // Host-side `NativeInput`: the native form IS this struct itself (built host-side
    // with `Field` and native integer values — no `String` mirror), and `leaves` renders
    // each field to its decimal under the compiler's structural-flatten names, so a
    // `#[circuit]` param of this type binds by name exactly as a gadget input does.
    let mut leaf_stmts = Vec::new();
    let mut schema_fields = Vec::new();
    for (fname, acc, ty) in &fields {
        let field_prefix = quote! { std::format!("{}.{}", prefix, #fname) };
        leaf_stmts.push(circuit_leaves(
            ty,
            &quote! { native.#acc },
            &field_prefix,
            0,
        )?);
        let ty_json = schema_type(ty)?;
        schema_fields.push(quote! {
            std::format!("{{\"name\":\"{}\",\"type\":{}}}", #fname, #ty_json)
        });
    }
    let name_lit = LitStr::new(&name.to_string(), name.span());

    let wasm_input = wasm_input_impl(name, data);
    Ok(quote! {
        #wasm_input

        #[automatically_derived]
        impl #name {
            /// Number of `Field` leaves this input flattens to — maintained by
            /// `#[derive(CircuitInput)]`, so you never recount by hand.
            pub const FIELD_LEN: usize = #n;

            /// Flatten into the circuit's `Field` leaves in structural order (fields in
            /// declaration order, arrays by index, nested structs inline) — the same order
            /// the compiler and the `From<Self> for [Field; FIELD_LEN]` impl use. Native
            /// integers convert with `Field::from` (free: they are already range-checked
            /// wires). Feed this straight to a hash gadget.
            pub fn to_fields(&self) -> [::xark::Field; #name::FIELD_LEN] {
                let mut out = [<::xark::Field as ::core::convert::From<u8>>::from(0u8); #name::FIELD_LEN];
                let mut __i = 0usize;
                #( #self_blocks )*
                let _ = __i;
                out
            }
        }

        #[automatically_derived]
        impl ::core::convert::From<#name> for [::xark::Field; #name::FIELD_LEN] {
            fn from(__v: #name) -> [::xark::Field; #name::FIELD_LEN] {
                let mut out = [<::xark::Field as ::core::convert::From<u8>>::from(0u8); #name::FIELD_LEN];
                let mut __i = 0usize;
                #( #blocks )*
                let _ = __i;
                out
            }
        }

        // `NativeInput` lives in `xark_prover` (a `std` crate); bring `std` in inside an
        // anonymous const so this also works from a `no_std`-under-`xark` crate's host build.
        #[cfg(not(xark))]
        const _: () = {
            extern crate std;
            use std::string::String;
            use std::vec::Vec;
            #[automatically_derived]
            impl ::xark_prover::NativeInput for #name {
                type Native = #name;
                fn leaves(native: &Self::Native, prefix: &str) -> Vec<(String, String)> {
                    let mut __out = Vec::new();
                    #( #leaf_stmts )*
                    __out
                }
                fn schema(defs: &mut std::collections::BTreeMap<String, String>) -> String {
                    if !defs.contains_key(#name_lit) {
                        // Reserve the name first so a type reached twice is described once.
                        defs.insert(String::from(#name_lit), String::new());
                        let fields: Vec<String> = std::vec![#( #schema_fields ),*];
                        defs.insert(
                            String::from(#name_lit),
                            std::format!("{{\"struct\":[{}]}}", fields.join(",")),
                        );
                    }
                    std::format!("{{\"ref\":\"{}\"}}", #name_lit)
                }
            }
        };
    })
}

/// The stable-frontend input binding for a `Field`-composed struct (`--cfg xark` on
/// `wasm32`): each field bound in declaration order under `<prefix>.<field>`, the
/// compiler's structural-flatten names.
fn wasm_input_impl(name: &syn::Ident, data: &DataStruct) -> TokenStream2 {
    let binds = data.fields.iter().enumerate().map(|(i, f)| {
        let fname = match &f.ident {
            Some(id) => id.to_string(),
            None => i.to_string(),
        };
        let lit = LitStr::new(&fname, name.span());
        let value = quote! { ::xark::wasm::input_field(__name, #lit, __vis) };
        match &f.ident {
            Some(id) => quote! { #id: #value },
            None => value,
        }
    });
    let ty_lit = LitStr::new(&name.to_string(), name.span());
    let ctor = match &data.fields {
        syn::Fields::Named(_) => quote! { #name { #( #binds ),* } },
        syn::Fields::Unnamed(_) => quote! { #name ( #( #binds ),* ) },
        syn::Fields::Unit => quote! { #name },
    };
    quote! {
        #[cfg(all(xark, target_arch = "wasm32"))]
        #[automatically_derived]
        impl ::xark::wasm::Input for #name {
            fn input(__name: &mut ::xark::wasm::NameBuf, __vis: u32) -> Self {
                ::xark::wasm::input_struct(__name, #ty_lit);
                #ctor
            }
        }
    }
}

/// Emit the flatten statements for one field/element `access` of type `ty`, returning
/// `(leaf count expression, statements)`. A `Field` or native `uN` is one leaf, arrays
/// recurse, and any other named type is a nested `#[derive(CircuitInput)]` struct that
/// contributes its own `to_fields()`. `depth` names loop variables so nesting doesn't
/// collide.
fn walk_type(
    ty: &Type,
    access: &TokenStream2,
    depth: usize,
) -> syn::Result<(TokenStream2, TokenStream2)> {
    match ty {
        Type::Path(tp) if tp.path.segments.last().is_some_and(|s| s.ident == "Field") => {
            Ok((quote! { 1usize }, quote! { out[__i] = #access; __i += 1; }))
        }
        _ if uint_type_bits(ty).is_some() => Ok((
            quote! { 1usize },
            quote! { out[__i] = <::xark::Field as ::core::convert::From<#ty>>::from(#access); __i += 1; },
        )),
        Type::Path(tp) if tp.path.is_ident("bool") => Err(syn::Error::new_spanned(
            ty,
            "`bool` is not a circuit input type yet; use `u8` (or `Field`) and constrain it \
             to 0/1 with `require_bool`",
        )),
        Type::Array(arr) => {
            let len = eval_usize_lit(&arr.len)?;
            let kv = format_ident!("__k{depth}");
            let (inner_count, inner) = walk_type(&arr.elem, &quote! { #access[#kv] }, depth + 1)?;
            let block = quote! {
                {
                    let mut #kv = 0usize;
                    while #kv < #len {
                        #inner
                        #kv += 1;
                    }
                }
            };
            Ok((quote! { (#len * #inner_count) }, block))
        }
        Type::Path(_) => {
            // A nested `#[derive(CircuitInput)]` struct: copy its own flatten in place.
            let kv = format_ident!("__k{depth}");
            let sub = format_ident!("__sub{depth}");
            Ok((
                quote! { <#ty>::FIELD_LEN },
                quote! {
                    {
                        let #sub = #access.to_fields();
                        let mut #kv = 0usize;
                        while #kv < <#ty>::FIELD_LEN {
                            out[__i] = #sub[#kv];
                            __i += 1;
                            #kv += 1;
                        }
                    }
                },
            ))
        }
        other => Err(syn::Error::new_spanned(
            other,
            "#[derive(CircuitInput)] fields must be `Field`, `u8`..`u128`, fixed arrays of \
             them, or another `#[derive(CircuitInput)]` struct; array lengths must be \
             integer literals",
        )),
    }
}

/// The schema JSON (a `String` expression) for one field type; see `<Fn>Inputs::schema`.
fn schema_type(ty: &Type) -> syn::Result<TokenStream2> {
    if let Type::Path(tp) = ty
        && tp.path.segments.last().is_some_and(|s| s.ident == "Field")
    {
        return Ok(quote! { String::from("\"field\"") });
    }
    if let Some(w) = uint_type_bits(ty) {
        let j = format!("{{\"uint\":{w}}}");
        return Ok(quote! { String::from(#j) });
    }
    match ty {
        Type::Array(arr) => {
            let len = eval_usize_lit(&arr.len)?;
            let inner = schema_type(&arr.elem)?;
            Ok(quote! {
                std::format!("{{\"array\":{{\"of\":{},\"len\":{}}}}}", #inner, #len)
            })
        }
        Type::Path(_) => Ok(quote! { <#ty as ::xark_prover::NativeInput>::schema(defs) }),
        other => Err(syn::Error::new_spanned(
            other,
            "unsupported #[derive(CircuitInput)] field type",
        )),
    }
}

/// `#[derive(Transparent)]` — generate the host-side [`NativeInput`] fan-out for a
/// transparent circuit type, so the leaf-name / limb contract (which must match the
/// compiler's structural flatten) is generated once, not hand-duplicated per gadget.
///
/// Two shapes:
///  * a **leaf** field element `{ limbs: [Field; N] }` marked `#[transparent(bits = B)]`:
///    native form `[u8; N*B/8]` (big-endian), flattening to `<prefix>.limbs[i]`.
///  * a **composite** of transparent fields (e.g. `{ x: Fq, y: Fq }`): native form is
///    the fields' native bytes concatenated, recursing under `<prefix>.<field>`.
///
/// The generated impl is `#[cfg(not(xark))]` — `NativeInput` is host-only.
///
/// [`NativeInput`]: https://docs.rs/xark-prover/latest/xark_prover/trait.NativeInput.html
#[proc_macro_derive(Transparent, attributes(transparent))]
pub fn derive_transparent(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    match transparent_impl(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Parse `#[transparent(bits = B)]` → `Some(B)` (leaf mode); `None` = composite.
fn parse_transparent_bits(attrs: &[Attribute]) -> syn::Result<Option<u32>> {
    for attr in attrs {
        if attr.path().is_ident("transparent") {
            let mut bits = None;
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("bits") {
                    let lit: LitInt = meta.value()?.parse()?;
                    bits = Some(lit.base10_parse::<u32>()?);
                    Ok(())
                } else {
                    Err(meta.error("expected `bits = <n>`"))
                }
            })?;
            return Ok(bits);
        }
    }
    Ok(None)
}

/// A leaf transparent type is `{ limbs: [Field; N] }`; return `N`.
fn leaf_limb_count(data: &DataStruct) -> syn::Result<usize> {
    let field = data.fields.iter().next().ok_or_else(|| {
        syn::Error::new_spanned(
            &data.fields,
            "a `#[transparent(bits = ..)]` leaf needs a `limbs: [Field; N]` field",
        )
    })?;
    match &field.ty {
        Type::Array(arr) => eval_usize_lit(&arr.len),
        other => Err(syn::Error::new_spanned(
            other,
            "a `#[transparent(bits = ..)]` leaf's field must be `[Field; N]`",
        )),
    }
}

fn transparent_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "#[derive(Transparent)] does not support generic types",
        ));
    }
    let data = match &input.data {
        Data::Struct(d) => d,
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "#[derive(Transparent)] only supports structs",
            ));
        }
    };

    let (native_ty, leaves_body) = if let Some(bits) = parse_transparent_bits(&input.attrs)? {
        // LEAF: `{ limbs: [Field; N] }`, native = big-endian `[u8; N*B/8]`.
        let n = leaf_limb_count(data)?;
        let bytes = n * (bits as usize) / 8;
        (
            quote! { [u8; #bytes] },
            quote! { ::xark_prover::limb_leaves(native, prefix, #n, #bits) },
        )
    } else {
        // COMPOSITE: native = concatenation of the fields' native bytes; recurse.
        let field_size = |fty: &Type| {
            quote! { ::core::mem::size_of::<<#fty as ::xark_prover::NativeInput>::Native>() }
        };
        let sizes: Vec<_> = data.fields.iter().map(|f| field_size(&f.ty)).collect();
        let native_ty = quote! { [u8; { 0usize #( + #sizes )* }] };

        let mut stmts = Vec::new();
        let mut offset = quote! { 0usize };
        for (i, field) in data.fields.iter().enumerate() {
            let fty = &field.ty;
            let fname = match &field.ident {
                Some(id) => id.to_string(),
                None => i.to_string(),
            };
            let size = field_size(fty);
            stmts.push(quote! {
                {
                    let __start = #offset;
                    let __end = __start + #size;
                    let __chunk: &<#fty as ::xark_prover::NativeInput>::Native =
                        ::core::convert::TryFrom::try_from(&native[__start..__end]).unwrap();
                    __out.extend(<#fty as ::xark_prover::NativeInput>::leaves(
                        __chunk,
                        &std::format!("{}.{}", prefix, #fname),
                    ));
                }
            });
            offset = quote! { #offset + #size };
        }
        (
            native_ty,
            quote! {
                let mut __out = Vec::new();
                #( #stmts )*
                __out
            },
        )
    };

    let wasm_input = wasm_input_impl(name, data);
    // `NativeInput` lives in `xark_prover` (a `std` crate) but a gadget crate is
    // `#![no_std]`, so bring `std` in inside an anonymous const (hygienic-derive pattern).
    Ok(quote! {
        #wasm_input

        #[cfg(not(xark))]
        const _: () = {
            extern crate std;
            use std::string::String;
            use std::vec::Vec;
            #[automatically_derived]
            impl ::xark_prover::NativeInput for #name {
                type Native = #native_ty;
                fn leaves(native: &Self::Native, prefix: &str) -> Vec<(String, String)> {
                    #leaves_body
                }
            }
        };
    })
}

/// Emit `NativeInput::leaves` push statements for a `Field`-composed value `access` of
/// circuit type `ty`, whose flatten prefix is the `String` expression `prefix`. A `Field`
/// renders to its decimal via [`Field::to_decimal`]; arrays recurse under `prefix[i]`; a
/// nested `NativeInput` type delegates under its own `prefix`. `depth` names loop vars.
/// Used by `#[derive(CircuitInput)]` to build the host-side leaf fan-out.
fn circuit_leaves(
    ty: &Type,
    access: &TokenStream2,
    prefix: &TokenStream2,
    depth: usize,
) -> syn::Result<TokenStream2> {
    match ty {
        Type::Path(tp) if tp.path.segments.last().is_some_and(|s| s.ident == "Field") => {
            Ok(quote! { __out.push((#prefix, #access.to_decimal())); })
        }
        _ if uint_type_bits(ty).is_some() => Ok(quote! {
            __out.push((#prefix, std::string::ToString::to_string(&#access)));
        }),
        Type::Array(arr) => {
            let len = eval_usize_lit(&arr.len)?;
            let kv = format_ident!("__k{depth}");
            let pv = format_ident!("__p{depth}");
            let inner = circuit_leaves(
                &arr.elem,
                &quote! { #access[#kv] },
                &quote! { std::format!("{}[{}]", #pv, #kv) },
                depth + 1,
            )?;
            Ok(quote! {
                {
                    let #pv = #prefix;
                    let mut #kv = 0usize;
                    while #kv < #len {
                        #inner
                        #kv += 1;
                    }
                }
            })
        }
        Type::Path(_) => Ok(quote! {
            __out.extend(<#ty as ::xark_prover::NativeInput>::leaves(&#access, &#prefix));
        }),
        other => Err(syn::Error::new_spanned(
            other,
            "#[derive(CircuitInput)] fields must be `Field`, fixed arrays of them, \
             or a type implementing `NativeInput`",
        )),
    }
}

/// A `usize` from an integer-literal length expression (`[Field; 32]` → `32`).
fn eval_usize_lit(e: &Expr) -> syn::Result<usize> {
    match e {
        Expr::Lit(ExprLit {
            lit: Lit::Int(li), ..
        }) => li.base10_parse::<usize>(),
        other => Err(syn::Error::new_spanned(
            other,
            "#[derive(CircuitInput)] array lengths must be integer literals",
        )),
    }
}
