/**
 * The envelope a client seals to the enclave, and the stream it gets back.
 *
 * Once verifyAttestation has produced a public key, this is what is done with
 * it. The client mints a session key, wraps it to that public key, and encrypts
 * the request under it. The Worker forwards bytes it cannot read; the enclave
 * unwraps, answers, and seals each piece of the answer back under the same
 * session key. Nothing between the two ends can read either direction, which is
 * the whole point — the Worker is trusted to relay and to count, not to know.
 *
 * ── Why the answer is a stream of pieces ──
 *
 * Chat streams. The reply arrives token by token and has to keep arriving that
 * way, so it cannot be sealed as one blob at the end without turning a
 * responsive interface into a long pause. Each piece is therefore sealed on its
 * own.
 *
 * Which creates a problem a single blob does not have. A relay that cannot read
 * the pieces can still reorder them, drop the last few, or replay yesterday's.
 * Every piece decrypts perfectly and the reader sees a plausible answer that is
 * not the one that was sent — the failure looks like the model being strange
 * rather than like an attack. So each piece carries its position and whether it
 * is the last, both bound into the encryption as associated data: a piece moved
 * or a stream cut short fails to open rather than opening as something else.
 *
 * ── Shapes ──
 *
 * RSA-OAEP-SHA-256 to wrap, because that is the key the Nitro Security Module
 * binds into the attestation document (enclave/src/attest.ts generates 2048-bit
 * RSA at boot). AES-256-GCM for the payload, which is authenticated encryption
 * and is what both WebCrypto and the platform libraries on iOS and Android give
 * without argument.
 */

/** Bytes on the wire are base64 so an envelope survives JSON. */
const b64 = (b: Uint8Array): string => {
  let s = "";
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s);
};

const unb64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** WebCrypto refuses views backed by a SharedArrayBuffer. */
function buf(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

export const ENVELOPE_VERSION = 1;

export type SealedRequest = {
  v: number;
  /** The session key, wrapped to the enclave's attested public key. */
  k: string;
  /** iv‖ciphertext for the request body. */
  c: string;
};

export type SealedChunk = {
  /** Position in the stream, from 0. Bound into the encryption. */
  i: number;
  /** Whether this is the last piece. Also bound in. */
  final: boolean;
  /** iv‖ciphertext. */
  c: string;
};

/* ── Session keys ─────────────────────────────────────────────────────────── */

export async function newSessionKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

async function importSession(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buf(raw), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** A fresh 12-byte IV per message. Random rather than a counter: the pieces of
 *  one stream share a key, and a counter that restarts is the one way to reuse
 *  an IV under GCM, which loses the key outright rather than one message. */
const iv = () => crypto.getRandomValues(new Uint8Array(12));

function join(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/* ── Request: client → enclave ────────────────────────────────────────────── */

/**
 * Seal a request to the enclave's attested public key.
 *
 * @param enclaveSpki the `publicKey` from a *verified* attestation document.
 *   Passing a key that came from anywhere else — a /public-key fetch, a cached
 *   value, the Worker — makes everything below decorative: whoever supplied the
 *   key can open the envelope.
 */
export async function sealRequest(
  enclaveSpki: Uint8Array,
  body: string,
): Promise<{ envelope: SealedRequest; session: CryptoKey }> {
  const session = await newSessionKey();
  const rawSession = new Uint8Array(await crypto.subtle.exportKey("raw", session));

  const wrapKey = await crypto.subtle.importKey(
    "spki",
    buf(enclaveSpki),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  const wrapped = new Uint8Array(
    await crypto.subtle.encrypt({ name: "RSA-OAEP" }, wrapKey, buf(rawSession)),
  );

  const nonce = iv();
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: buf(nonce) },
      session,
      buf(new TextEncoder().encode(body)),
    ),
  );

  return {
    envelope: { v: ENVELOPE_VERSION, k: b64(wrapped), c: b64(join(nonce, ct)) },
    session,
  };
}

/**
 * Open a request inside the enclave.
 *
 * Returns the body and the session key the answer must be sealed under. The
 * private key never leaves the enclave and there is no accessor for it — this
 * takes the unwrap operation as a function so the caller passes
 * `decryptToEnclave` from attest.ts rather than the key itself.
 */
export async function openRequest(
  envelope: SealedRequest,
  unwrap: (ciphertext: Uint8Array) => Promise<Uint8Array>,
): Promise<{ body: string; session: CryptoKey }> {
  if (envelope?.v !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version ${envelope?.v}`);
  }
  const rawSession = await unwrap(unb64(envelope.k));
  if (rawSession.length !== 32) throw new Error("session key is not 32 bytes");
  const session = await importSession(rawSession);

  const blob = unb64(envelope.c);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buf(blob.subarray(0, 12)) },
    session,
    buf(blob.subarray(12)),
  );
  return { body: new TextDecoder().decode(plain), session };
}

/* ── Response: enclave → client, in pieces ────────────────────────────────── */

/**
 * What binds a piece to its place in the stream.
 *
 * GCM's associated data is authenticated but not encrypted, so this costs
 * nothing to carry and cannot be changed without the piece failing to open. A
 * relay may still drop or reorder pieces — it just cannot do so undetectably,
 * which is the difference between a broken stream and a forged one.
 */
const aad = (index: number, final: boolean): Uint8Array =>
  new TextEncoder().encode(`secure-ai/v${ENVELOPE_VERSION}/${index}/${final ? "final" : "more"}`);

export async function sealChunk(
  session: CryptoKey,
  index: number,
  text: string,
  final: boolean,
): Promise<SealedChunk> {
  const nonce = iv();
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: buf(nonce), additionalData: buf(aad(index, final)) },
      session,
      buf(new TextEncoder().encode(text)),
    ),
  );
  return { i: index, final, c: b64(join(nonce, ct)) };
}

/**
 * Reads a sealed stream, in order, and refuses anything else.
 *
 * Stateful on purpose. The checks it makes are about the sequence rather than
 * any single piece, and a caller holding the state itself is a caller who will
 * eventually forget one of them.
 */
export class SealedStreamReader {
  private session: CryptoKey;
  private next = 0;
  private done = false;

  constructor(session: CryptoKey) {
    this.session = session;
  }

  /** True once the piece marked final has been read. */
  get complete(): boolean {
    return this.done;
  }

  async open(chunk: SealedChunk): Promise<string> {
    if (this.done) throw new Error("stream already ended");
    /* The index is checked here as well as being bound into the encryption.
       Both are needed: the binding stops a piece being passed off as another,
       and this stops the same piece being replayed in its own position. */
    if (chunk.i !== this.next) {
      throw new Error(`out of order: expected piece ${this.next}, got ${chunk.i}`);
    }

    const blob = unb64(chunk.c);
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: buf(blob.subarray(0, 12)),
        additionalData: buf(aad(chunk.i, chunk.final)),
      },
      this.session,
      buf(blob.subarray(12)),
    );

    this.next += 1;
    this.done = chunk.final;
    return new TextDecoder().decode(plain);
  }

  /**
   * Call when the transport says there is no more.
   *
   * A stream that stops without a final piece is the failure this exists to
   * catch: every piece opened, the text reads as a complete answer, and the
   * last part of it is missing because something in the middle stopped
   * relaying. Silence is not an ending.
   */
  finish(): void {
    if (!this.done) throw new Error("stream ended without a final piece");
  }
}
