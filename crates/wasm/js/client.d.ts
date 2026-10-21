/**
 * A BN254 field element, checked when it's made: `new Field(x)` takes a `bigint`,
 * a safe integer, a decimal or `0x`-hex string, little-endian bytes (a `Uint8Array`
 * of at most 32, as proofs and Rust's `Field::from_le_bytes` have them), or another
 * `Field`, and throws unless it's an integer in [0, p).
 */
export class Field {
  /** The field's modulus, p (BN254's scalar field). */
  static readonly MODULUS: bigint;
  /** The element, in [0, p). */
  readonly value: bigint;
  constructor(x: Field | bigint | number | string | Uint8Array);
  /** From big-endian bytes (at most 32), as some outside formats have them. */
  static fromBeBytes(bytes: Uint8Array): Field;
  /** Whether `other` is the same element. */
  equals(other: Field | bigint | number | string | Uint8Array): boolean;
  /** The element as 32 little-endian bytes, as proofs have it. */
  toBytes(): Uint8Array;
  /** Decimal. */
  toString(): string;
  toJSON(): string;
}

/** Bytes: a `Uint8Array`, byte values, or a `0x`-hex string. */
export type Bytes = Uint8Array | readonly number[] | string;

/** A proof and the public inputs it proves. */
export class Proof<PublicValues> {
  /** The Groth16 proof. */
  readonly proofBytes: Uint8Array;
  /** The public inputs, decoded. */
  readonly publicInputs: PublicValues;
  /** The public inputs as their canonical bytes (`public_inputs.bin`). */
  readonly publicInputBytes: Uint8Array;
  constructor(proofBytes: Uint8Array, publicInputs: PublicValues, publicInputBytes: Uint8Array);
  /**
   * The proof and its public inputs as one blob to send: a verifier's `verify`
   * and `decode` read it.
   */
  toBytes(): Uint8Array;
}

/** The parts of `@blueshift-gg/xark-wasm` a client uses (any of its builds). */
export interface Wasm {
  prove(circuit: Uint8Array, provingKey: Uint8Array, inputs: Record<string, string>, sources?: string): { proof: Uint8Array; publicInputs: Uint8Array };
  verify(verifyingKey: Uint8Array, proof: Uint8Array, publicInputs: Uint8Array): boolean;
  encodeInputs(schema: string, inputs: string): Record<string, string>;
  encodePublicInputs(schema: string, publicInputs: string): Uint8Array;
  decodePublicValues(schema: string, publicInputs: Uint8Array): string;
  valueFields(schema: string, typeName: string, value: string): string[];
}

/** `client.wasm`, the circuit's Rust functions: its bytes, or the compiled module. */
export type ClientWasm = BufferSource | WebAssembly.Module;

/** The build output proving needs (`target/xark/<circuit>/`). */
export interface ProverArtifacts {
  /** `circuit.xbc`. */
  circuit: Uint8Array;
  /** `pk.bin`. */
  provingKey: Uint8Array;
  /** `sources.json`, as text: inputs that fail a check name its source line. */
  sources?: string;
  /** `client.wasm`, for the circuit's Rust functions. */
  client?: ClientWasm;
}

/** The build output verifying needs. */
export interface VerifierArtifacts {
  /** `vk.bin`. */
  verifyingKey: Uint8Array;
  /** `client.wasm`, for the circuit's Rust functions. */
  client?: ClientWasm;
}

export interface LoadOptions {
  /** Passed to each `fetch`. */
  request?: RequestInit;
}

/** What provers and verifiers share. */
export class Session<PublicInputs, PublicValues, Structs> {
  /** The public inputs as their canonical bytes (`public_inputs.bin`). */
  encodePublicInputs(publicInputs: PublicInputs): Uint8Array;
  /** Canonical public-input bytes, decoded. */
  decodePublicInputs(bytes: Uint8Array): PublicValues;
  /**
   * A `Proof` from `proof.toBytes()`, with its public inputs decoded. This doesn't
   * verify it: `verify` does. Throws if `bytes` isn't a serialized proof.
   */
  decode(bytes: Uint8Array): Proof<PublicValues>;
  /**
   * A value's field elements in input order, as `to_fields()` gives them in Rust:
   * hash them as the circuit does (`wasm.poseidon2(fields.map(String))`).
   */
  fields<K extends keyof Structs & string>(type: K, value: Structs[K]): Field[];
}

/** Proves a circuit: from `circuit.prover(wasm, …)`. */
export class Prover<Inputs, PublicInputs, PublicValues, Structs = {}> extends Session<PublicInputs, PublicValues, Structs> {
  private constructor();
  /**
   * Prove `inputs`. Throws if one is malformed (naming it), or if they fail a
   * check (naming its source line when `sources` was given).
   */
  prove(inputs: Inputs): Proof<PublicValues>;
}

/** Verifies a circuit's proofs: from `circuit.verifier(wasm, …)`. */
export class Verifier<PublicInputs, PublicValues, Structs = {}> extends Session<PublicInputs, PublicValues, Structs> {
  private constructor();
  /**
   * Whether `proof` (a `Proof`, or its `toBytes()`) is valid. With `publicInputs`,
   * whether it proves those: pass the ones you require (a policy, a root), or a
   * proof of other public inputs passes.
   */
  verify(proof: Proof<PublicValues> | Uint8Array, publicInputs?: PublicInputs | Uint8Array): boolean;
}

/** A circuit as its generated client describes it. */
export interface CircuitSpec<PublicValues> {
  /** The circuit's name (`zk_kyc`). */
  name: string;
  /** Its `schema.json`. */
  schema: string;
  /** Revives decoded public inputs (dates, fields, bytes) from xark-wasm's JSON. */
  decodePublic(json: any): PublicValues;
  /** Whether it has Rust functions (`client.wasm`). */
  client: boolean;
}

/**
 * One circuit: makes its provers and verifiers, from a URL serving a copy of its
 * build output (`target/xark/<circuit>/`, relative to the page in a browser) or
 * from the bytes. Made from a URL, either also loads `client.wasm` when the
 * circuit has Rust functions; a missing `sources.json` or `client.wasm` is skipped.
 */
export class Circuit<Inputs, PublicInputs, PublicValues, Structs = {}> {
  constructor(spec: CircuitSpec<PublicValues>);
  /** The circuit's name. */
  readonly name: string;
  /** The circuit's `schema.json`. */
  readonly schema: string;
  prover(
    wasm: Wasm,
    from: string | URL | ProverArtifacts,
    options?: LoadOptions,
  ): Promise<Prover<Inputs, PublicInputs, PublicValues, Structs>>;
  /** `from` may also be `vk.bin`'s bytes. */
  verifier(
    wasm: Wasm,
    from: string | URL | Uint8Array | VerifierArtifacts,
    options?: LoadOptions,
  ): Promise<Verifier<PublicInputs, PublicValues, Structs>>;
  /** Load `client.wasm` yourself (a prover or verifier made from a URL does). */
  initClient(wasm: ClientWasm): Promise<void>;
  /** Run one of the circuit's Rust functions (the generated client calls it). */
  call(name: string, args: unknown[]): any;
}

/** JSON for xark-wasm (the generated client calls it). */
export function toJson(value: unknown): string;
/** `0x`-hex to bytes (the generated client calls it). */
export function fromHex(s: string): Uint8Array;
