// xark-client — verify xark zero-knowledge proofs and build on-chain calldata.
//
// Construct a client from the xark-wasm module and a circuit's verifying key
// (`vk.bin`, written by `xark setup`), then verify the proof bundles
// `xark prove` produces:
//
//   import * as wasm from "@blueshift-gg/xark-wasm"; // node, web (after `await init()`), or bundler
//   import { XarkClient } from "xark-client";
//
//   const client = new XarkClient(wasm, vkBytes);
//   client.verify(bundle);                // true / false
//   const data = client.calldata(bundle); // packed proof ‖ public bytes
//
// The wasm module is passed in rather than imported, so the same code works with
// any of xark-wasm's builds. To prove in JS too, use xark-wasm's `prove`, or the
// typed client `xark codegen ts` generates.

/** The part of the xark-wasm module this client uses. */
export interface XarkWasm {
  verify(verifyingKey: Uint8Array, proof: Uint8Array, publicInputs: Uint8Array): boolean;
}

/** A proof bundle as written by `xark prove` (`<name>-<hash>.proof.json`). */
export interface ProofBundle {
  circuit: string;
  circuit_hash: string;
  proof_sha256: string;
  /** The public inputs as decimal strings, in proof order. */
  public_inputs: string[];
  /** `proof.bin`: the canonical proof bytes `verify` takes, as hex. */
  proof_bin: string;
  /** `public_inputs.bin`: the canonical public-input bytes `verify` takes, as hex. */
  public_inputs_bin: string;
  calldata: {
    endianness: string;
    hex: string;
    proof_hex: string;
    public_inputs_hex: string;
  };
}

/** Decode a `0x…`/bare hex string into bytes (browser- and Node-safe). */
export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("hexToBytes: odd-length hex string");
  // Reject non-hex up front — otherwise a bad pair parses to NaN, which
  // Uint8Array silently coerces to 0 (wrong bytes, no error).
  if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error("hexToBytes: invalid hex string");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** A verifier for one circuit, built from its verifying key (`vk.bin`). */
export class XarkClient {
  readonly verifyingKey: Uint8Array;

  constructor(
    private readonly wasm: XarkWasm,
    verifyingKey: Uint8Array | ArrayBuffer,
  ) {
    this.verifyingKey =
      verifyingKey instanceof Uint8Array ? verifyingKey : new Uint8Array(verifyingKey);
  }

  /**
   * Verify a proof bundle (as written by `xark prove`). `false` for a proof that
   * doesn't verify; throws on malformed bytes.
   */
  verify(bundle: ProofBundle): boolean {
    return this.verifyRaw(hexToBytes(bundle.proof_bin), hexToBytes(bundle.public_inputs_bin));
  }

  /** Verify raw `proof.bin` / `public_inputs.bin` bytes. */
  verifyRaw(proof: Uint8Array, publicInputs: Uint8Array): boolean {
    return this.wasm.verify(this.verifyingKey, proof, publicInputs);
  }

  /**
   * The packed verifier calldata: `proof (256 B) || public_inputs (N * 32 B)`,
   * little-endian — what a verifier built with `xark export` consumes. Your
   * program owns the accounts and any instruction discriminator; drop these
   * bytes where your verifier expects the proof.
   */
  calldata(bundle: ProofBundle): Uint8Array {
    return hexToBytes(bundle.calldata.hex);
  }
}
