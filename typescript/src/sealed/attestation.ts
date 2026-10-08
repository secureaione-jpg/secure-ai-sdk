/**
 * Checking that the enclave is the enclave.
 *
 * The other half of enclave/src/attest.ts, which says outright that it does not
 * verify — "a verifier that lives next to the thing it verifies is theatre".
 * This is the sceptic's half, and it is the piece the whole design rests on.
 *
 * The point is not that a signed document exists. It is that a client refuses
 * to send anything until it has one it believes. Sealing to a public key
 * fetched over HTTPS proves nothing at all: whoever serves the key can read
 * what is sealed to it, and the Worker is exactly the party this is meant to
 * exclude. What makes the key trustworthy is that the Nitro Security Module
 * signed it *into* a document that also carries PCR0 — the hash of the running
 * image — so a verified document says "this key belongs to an enclave running
 * this exact code, and to nothing else".
 *
 * Which means every check below is load-bearing, and skipping any one of them
 * quietly returns the system to trusting the Worker:
 *
 *   the signature      or the document is whatever the relay wants it to say
 *   the chain          or anyone with a self-signed cert is Amazon
 *   the root pin       or the chain proves only that a chain exists
 *   the nonce          or a real document from last week is replayed forever
 *   the validity       or a retired image's key keeps working
 *   PCR0               or it is a genuine enclave running somebody else's code
 *
 * No dependencies, and none available: this has to run in a browser, in a
 * Cloudflare Worker, and be portable to Swift and Kotlin without dragging a
 * CBOR library into three more places. Everything here is the subset of CBOR
 * and X.509 that an attestation document actually uses, and no more.
 */

/* ── CBOR ─────────────────────────────────────────────────────────────────── */

type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | CborValue[]
  | Map<CborValue, CborValue>;

class Reader {
  bytes: Uint8Array;
  pos: number;

  /* Written out rather than as constructor parameter properties: those are one
     of the few TypeScript constructs with no JavaScript equivalent, so a file
     using them cannot be run by type-stripping alone — which is how this module
     gets loaded in a scratch check, and how a port to another runtime starts. */
  constructor(bytes: Uint8Array, pos = 0) {
    this.bytes = bytes;
    this.pos = pos;
  }

  private need(n: number): void {
    if (this.pos + n > this.bytes.length) throw new Error("cbor: truncated");
  }

  byte(): number {
    this.need(1);
    return this.bytes[this.pos++];
  }

  take(n: number): Uint8Array {
    this.need(n);
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** The argument encoded in the low five bits, per RFC 8949 §3. */
  private argument(info: number): number {
    if (info < 24) return info;
    if (info === 24) return this.byte();
    if (info === 25) return (this.byte() << 8) | this.byte();
    if (info === 26) {
      // Shift arithmetic would go negative at bit 31; multiply instead.
      return this.byte() * 0x1000000 + ((this.byte() << 16) | (this.byte() << 8) | this.byte());
    }
    if (info === 27) {
      let n = 0;
      for (let i = 0; i < 8; i += 1) n = n * 256 + this.byte();
      // Timestamps are milliseconds since epoch and fit comfortably; anything
      // past 2^53 is not a length or a time this format should be carrying.
      if (!Number.isSafeInteger(n)) throw new Error("cbor: integer too large");
      return n;
    }
    throw new Error(`cbor: bad argument ${info}`);
  }

  /** The end of an indefinite-length item. */
  private atBreak(): boolean {
    if (this.bytes[this.pos] === 0xff) {
      this.pos += 1;
      return true;
    }
    return false;
  }

  value(): CborValue {
    const initial = this.byte();
    const major = initial >> 5;
    const info = initial & 0x1f;

    /* Info 31 is an indefinite length: the item runs until a break byte rather
       than declaring how long it is. Worth spelling out because it is not the
       shape a reading of RFC 8949 leaves you expecting, and it is what the
       Nitro Security Module actually emits — the attestation document is an
       indefinite-length map (0xbf … 0xff). Written without this, the decoder
       failed on the tenth byte of every real document while passing every
       hand-made test, which is the wrong way round. */
    const indefinite = info === 31;

    switch (major) {
      case 0:
        return this.argument(info);
      case 1:
        return -1 - this.argument(info);
      case 2:
        return this.take(this.argument(info));
      case 3:
        return new TextDecoder().decode(this.take(this.argument(info)));
      case 4: {
        const arr: CborValue[] = [];
        if (indefinite) {
          while (!this.atBreak()) arr.push(this.value());
          return arr;
        }
        const n = this.argument(info);
        for (let i = 0; i < n; i += 1) arr.push(this.value());
        return arr;
      }
      case 5: {
        const map = new Map<CborValue, CborValue>();
        const put = () => {
          const k = this.value();
          map.set(typeof k === "string" || typeof k === "number" ? k : JSON.stringify(k), this.value());
        };
        if (indefinite) {
          while (!this.atBreak()) put();
          return map;
        }
        const n = this.argument(info);
        for (let i = 0; i < n; i += 1) put();
        return map;
      }
      case 6:
        // A tag. Nothing in an attestation document is tagged, and a decoder
        // that skips tags it does not understand is a decoder that can be
        // handed a different value than the signer signed.
        throw new Error("cbor: unexpected tag");
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 23) return null; // undefined
        throw new Error(`cbor: unsupported simple value ${info}`);
      default:
        throw new Error("cbor: unreachable");
    }
  }
}

/** Decode one CBOR value, and insist it is the whole input. Trailing bytes
 *  after a valid value are the classic way two parsers disagree about what was
 *  signed. */
export function cborDecode(bytes: Uint8Array): CborValue {
  const r = new Reader(bytes);
  const v = r.value();
  if (r.pos !== bytes.length) throw new Error("cbor: trailing bytes");
  return v;
}

/** Encode a definite-length byte string or array header plus payload. Only what
 *  Sig_structure needs. */
function cborHead(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 0x100) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 0x10000) return new Uint8Array([(major << 5) | 25, n >> 8, n & 0xff]);
  return new Uint8Array([(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function cborBytes(b: Uint8Array): Uint8Array {
  return concat(cborHead(2, b.length), b);
}

function cborText(s: string): Uint8Array {
  const b = new TextEncoder().encode(s);
  return concat(cborHead(3, b.length), b);
}

/* ── X.509, the parts a chain check needs ─────────────────────────────────── */

/** One DER element: its tag, its contents, and where the next one starts. */
type Der = { tag: number; content: Uint8Array; start: number; end: number };

function derRead(bytes: Uint8Array, at: number): Der {
  const tag = bytes[at];
  let i = at + 1;
  let len = bytes[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("der: unsupported length");
    len = 0;
    for (let k = 0; k < n; k += 1) len = (len << 8) | bytes[i++];
  }
  if (i + len > bytes.length) throw new Error("der: truncated");
  return { tag, content: bytes.subarray(i, i + len), start: at, end: i + len };
}

/** The children of a constructed element, in order. */
function derChildren(content: Uint8Array): Der[] {
  const out: Der[] = [];
  let at = 0;
  while (at < content.length) {
    const el = derRead(content, at);
    out.push(el);
    at = el.end;
  }
  return out;
}

export type Certificate = {
  /** Exactly the bytes the issuer signed. */
  tbs: Uint8Array;
  /** Raw r‖s, converted from the DER SEQUENCE an X.509 signature carries. */
  signature: Uint8Array;
  /** SubjectPublicKeyInfo, ready for importKey("spki", …). */
  spki: Uint8Array;
  notBefore: number;
  notAfter: number;
  subject: Uint8Array;
  issuer: Uint8Array;
  der: Uint8Array;
};

/** YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ. */
function derTime(el: Der): number {
  const s = new TextDecoder().decode(el.content);
  const utc = el.tag === 0x17; // UTCTime, two-digit year
  const y = utc ? Number(s.slice(0, 2)) : Number(s.slice(0, 4));
  const year = utc ? (y >= 50 ? 1900 + y : 2000 + y) : y;
  const o = utc ? 2 : 4;
  return Date.UTC(
    year,
    Number(s.slice(o, o + 2)) - 1,
    Number(s.slice(o + 2, o + 4)),
    Number(s.slice(o + 4, o + 6)),
    Number(s.slice(o + 6, o + 8)),
    Number(s.slice(o + 8, o + 10)) || 0,
  );
}

/**
 * An ECDSA signature in a certificate is DER — SEQUENCE { INTEGER r, INTEGER s }
 * — and WebCrypto wants the two integers concatenated, fixed width, unpadded.
 * The conversion is where a verifier quietly breaks on one certificate in a
 * few hundred: DER INTEGERs are signed, so a value whose top bit is set gains
 * a leading zero byte, and one that does not need the full width is short.
 */
function derSigToRaw(sig: Uint8Array, size: number): Uint8Array {
  const seq = derRead(sig, 0);
  const [r, s] = derChildren(seq.content);
  const out = new Uint8Array(size * 2);
  for (const [i, part] of [r, s].entries()) {
    let b = part.content;
    while (b.length > size && b[0] === 0) b = b.subarray(1);
    if (b.length > size) throw new Error("der: signature integer too long");
    out.set(b, i * size + (size - b.length));
  }
  return out;
}

export function parseCertificate(der: Uint8Array): Certificate {
  const cert = derRead(der, 0);
  const [tbsEl, , sigEl] = derChildren(cert.content);

  /* Sliced out of the parent's *content*, not out of `der`.
   *
   * derChildren reports offsets relative to the buffer it was handed, and the
   * first version of this file used them to index the whole certificate — so
   * every extracted field was shifted by the length of the enclosing header.
   * The failure was not a parse error: lengths came out plausible (a 410-byte
   * tbs, a 120-byte key) and the first thing to notice was WebCrypto refusing
   * the key as "Invalid keyData", four steps later and describing nothing.
   * Had the shift landed on a boundary that still imported, this would have
   * been a verifier checking a signature over the wrong bytes. */
  const tbs = cert.content.subarray(tbsEl.start, tbsEl.end);

  const fields = derChildren(tbsEl.content);
  // [0] version is optional and context-tagged; everything shifts if present.
  const base = fields[0].tag === 0xa0 ? 1 : 0;
  const issuer = fields[base + 2];
  const validity = derChildren(fields[base + 3].content);
  const subject = fields[base + 4];
  const spkiEl = fields[base + 5];

  // BIT STRING: first content byte is the count of unused bits, always 0 here.
  const sigBits = sigEl.content.subarray(1);

  return {
    tbs,
    signature: derSigToRaw(sigBits, 48), // P-384
    spki: tbsEl.content.subarray(spkiEl.start, spkiEl.end),
    notBefore: derTime(validity[0]),
    notAfter: derTime(validity[1]),
    subject: subject.content,
    issuer: issuer.content,
    der,
  };
}

const same = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((v, i) => v === b[i]);

async function verifyP384(
  spki: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "spki",
    copy(spki),
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, copy(signature), copy(message));
}

/** WebCrypto refuses a view backed by a SharedArrayBuffer, and every value here
 *  is a subarray of one buffer. */
function copy(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

/**
 * SHA-256 of the AWS Nitro Enclaves root certificate, DER.
 *
 * The anchor everything else hangs from. A verified chain says only that some
 * chain exists; this is what makes it Amazon's — so it is a constant in the
 * source, shipped inside each client, and never read from the document being
 * checked.
 *
 * Provenance, because a pin nobody can retrace is a magic number: fetched from
 * https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip on
 * 2026-09-04 (zip SHA-256 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c),
 * converted to DER, and compared against the root in a live attestation from
 * enclave-v8. Identical byte for byte. It was worth doing in that order: the
 * value was first taken from the enclave's own chain, which would have pinned
 * whatever an attacker put there.
 *
 * Subject and issuer C=US, O=Amazon, OU=AWS, CN=aws.nitro-enclaves; valid
 * 2019-10-28 to 2049-10-28.
 */
export const NITRO_ROOT_SHA256 =
  "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

/* ── The document ─────────────────────────────────────────────────────────── */

export type AttestationDocument = {
  moduleId: string;
  timestamp: number;
  /** Index → hex. PCR0 is the image; PCR1 the kernel; PCR2 the application. */
  pcrs: Record<number, string>;
  publicKey: Uint8Array | null;
  userData: Uint8Array | null;
  nonce: Uint8Array | null;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
};

export type VerifyOptions = {
  /** What the client sent. A document that does not echo it is a replay. */
  nonce: string;
  /** PCR0 values this client will talk to, lowercase hex. Empty means refuse
   *  everything, which is the right default for a caller that forgot. */
  trustedPCR0: string[];
  /** SHA-256 of the AWS Nitro root, hex. Pinned by the caller, never taken
   *  from the document — a chain that vouches for its own root is a circle. */
  rootFingerprint: string;
  /** For tests, and for reasoning about a document captured earlier. */
  now?: number;
  /** How far the document's timestamp may be from now. Nitro leaf certificates
   *  live about three hours; this is about the document, not the cert. */
  maxAgeMs?: number;
};

export type VerifyResult =
  | { ok: true; document: AttestationDocument; publicKey: Uint8Array; pcr0: string }
  | { ok: false; reason: string };

const hex = (b: Uint8Array) =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join("");

async function sha256Hex(b: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", copy(b))));
}

function field<T>(doc: Map<CborValue, CborValue>, name: string): T {
  return doc.get(name) as T;
}

/**
 * Verify a COSE_Sign1 attestation document, and return the public key it binds
 * only if every check passes.
 *
 * Returns a reason rather than throwing, because the caller's job is to refuse
 * and say why — an exception in this path tends to get caught somewhere that
 * turns it into a retry.
 */
export async function verifyAttestation(
  documentB64: string,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const now = opts.now ?? Date.now();
  const maxAge = opts.maxAgeMs ?? 3 * 60 * 60 * 1000;

  let cose: CborValue[];
  let payload: Uint8Array;
  let protectedBytes: Uint8Array;
  let signature: Uint8Array;
  let doc: Map<CborValue, CborValue>;
  try {
    const raw = Uint8Array.from(atob(documentB64), (c) => c.charCodeAt(0));
    cose = cborDecode(raw) as CborValue[];
    if (!Array.isArray(cose) || cose.length !== 4) return { ok: false, reason: "not a COSE_Sign1" };
    [protectedBytes, , payload, signature] = cose as [Uint8Array, unknown, Uint8Array, Uint8Array];
    doc = cborDecode(payload) as Map<CborValue, CborValue>;
    if (!(doc instanceof Map)) return { ok: false, reason: "document is not a map" };
  } catch (err) {
    return { ok: false, reason: `malformed: ${err instanceof Error ? err.message : "unknown"}` };
  }

  // ES384 and nothing else. An algorithm field the verifier honours is an
  // algorithm an attacker can choose.
  const header = cborDecode(protectedBytes) as Map<CborValue, CborValue>;
  if (header.get(1) !== -35) return { ok: false, reason: "signature algorithm is not ES384" };

  const parsed: AttestationDocument = {
    moduleId: field<string>(doc, "module_id"),
    timestamp: field<number>(doc, "timestamp"),
    pcrs: {},
    publicKey: field<Uint8Array | null>(doc, "public_key") ?? null,
    userData: field<Uint8Array | null>(doc, "user_data") ?? null,
    nonce: field<Uint8Array | null>(doc, "nonce") ?? null,
    certificate: field<Uint8Array>(doc, "certificate"),
    cabundle: field<Uint8Array[]>(doc, "cabundle"),
  };
  const pcrMap = doc.get("pcrs") as Map<CborValue, CborValue>;
  if (pcrMap instanceof Map) {
    for (const [k, v] of pcrMap) parsed.pcrs[Number(k)] = hex(v as Uint8Array);
  }

  if (!parsed.certificate || !Array.isArray(parsed.cabundle) || parsed.cabundle.length === 0) {
    return { ok: false, reason: "no certificate chain" };
  }

  /* The nonce, before anything expensive. A document that does not echo what
     this client just sent is a document about some other conversation, however
     genuine its signature. */
  const wantNonce = new TextEncoder().encode(opts.nonce);
  if (!parsed.nonce || !same(parsed.nonce, wantNonce)) {
    return { ok: false, reason: "nonce does not match — replayed or not ours" };
  }

  if (!Number.isFinite(parsed.timestamp)) return { ok: false, reason: "no timestamp" };
  if (Math.abs(now - parsed.timestamp) > maxAge) {
    return { ok: false, reason: `document is ${Math.round((now - parsed.timestamp) / 60000)} minutes old` };
  }

  /* The root, pinned. cabundle[0] is the root the document claims; comparing it
     against a fingerprint the client shipped with is the only step that
     converts "signed by somebody" into "signed by Amazon". Without it a chain
     an attacker generated verifies perfectly against its own root. */
  const claimedRoot = parsed.cabundle[0];
  const rootFp = await sha256Hex(claimedRoot);
  if (rootFp !== opts.rootFingerprint.toLowerCase()) {
    return { ok: false, reason: `root is not the pinned AWS root (${rootFp})` };
  }

  /* Chain: root, intermediates…, then the leaf that signed the document. Each
     certificate's tbs must verify under the previous one's key, and each must
     be inside its validity window at the time we are checking. */
  const chain = [...parsed.cabundle, parsed.certificate].map(parseCertificate);
  for (let i = 0; i < chain.length; i += 1) {
    const cert = chain[i];
    if (now < cert.notBefore || now > cert.notAfter) {
      return { ok: false, reason: `certificate ${i} is outside its validity window` };
    }
    const issuer = i === 0 ? cert : chain[i - 1];
    if (i > 0 && !same(cert.issuer, issuer.subject)) {
      return { ok: false, reason: `certificate ${i} is not issued by the one before it` };
    }
    try {
      if (!(await verifyP384(issuer.spki, cert.signature, cert.tbs))) {
        return { ok: false, reason: `certificate ${i} signature does not verify` };
      }
    } catch {
      return { ok: false, reason: `certificate ${i} could not be checked` };
    }
  }

  /* The document itself, under the leaf's key.
   *
   * COSE signs a Sig_structure, not the payload: ["Signature1", protected,
   * external_aad, payload]. Signing the payload directly is the mistake that
   * makes a verifier accept a document whose protected header — the algorithm —
   * has been changed. */
  const sigStructure = concat(
    cborHead(4, 4),
    cborText("Signature1"),
    cborBytes(protectedBytes),
    cborBytes(new Uint8Array(0)),
    cborBytes(payload),
  );
  const leaf = chain[chain.length - 1];
  try {
    if (!(await verifyP384(leaf.spki, signature, sigStructure))) {
      return { ok: false, reason: "document signature does not verify" };
    }
  } catch {
    return { ok: false, reason: "document signature could not be checked" };
  }

  /* And finally what it says. Everything above establishes that a real Nitro
     enclave produced this; PCR0 is the part that says which code it is
     running. An empty allowlist refuses, because a caller that forgot to say
     what it trusts has not decided to trust anything. */
  const pcr0 = parsed.pcrs[0];
  if (!pcr0) return { ok: false, reason: "no PCR0 in the document" };
  const trusted = opts.trustedPCR0.map((p) => p.toLowerCase());
  if (!trusted.includes(pcr0.toLowerCase())) {
    return { ok: false, reason: `PCR0 ${pcr0} is not one this client trusts` };
  }

  if (!parsed.publicKey || parsed.publicKey.length === 0) {
    return { ok: false, reason: "the document binds no public key" };
  }

  return { ok: true, document: parsed, publicKey: parsed.publicKey, pcr0 };
}
