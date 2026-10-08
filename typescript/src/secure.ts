/**
 * Secure mode: a conversation nobody between you and the model can read.
 *
 * The ordinary API redacts on our servers, which means our servers see the
 * text for as long as that takes. This path does not. The conversation is
 * sealed here, in your process, to a key that exists only inside an AWS Nitro
 * enclave — after checking a document signed by AWS's own hardware that says
 * exactly which program holds that key. Our Worker relays the envelope
 * without being able to open it; the enclave redacts, calls the model, puts
 * the real values back and seals the answer to you.
 *
 * If the enclave cannot prove what it is running, nothing is sent. There is
 * no fallback to the readable path, by design.
 *
 * src/sealed/ is the web app's own verifier and envelope, copied unchanged —
 * the SDK checks an enclave exactly as the app does.
 */

import { NITRO_ROOT_SHA256, verifyAttestation } from "./sealed/attestation.js";
import { sealRequest, SealedStreamReader, type SealedChunk } from "./sealed/envelope.js";

export interface SecureMessage {
  role: "user" | "assistant";
  content: string;
}

export interface SecureChatOptions {
  messages: SecureMessage[];
  system?: string;
  /** A model from `GET /v1/sealed`. Omitted: the default listed there. */
  model?: string;
  /** Each piece of the answer as it opens. */
  onText?: (piece: string) => void;
}

/** What `GET /v1/sealed` says. */
export interface SealedInfo {
  available: boolean;
  enclave: string;
  images: string[];
  models: Array<{ id: string; provider: string }>;
  default_model: string;
  max_output_tokens: number;
}

/**
 * Could not send in Secure mode. `reason` says which kind of no:
 * "unverified" — the enclave could not prove what it runs, so nothing was
 * sent; "unreachable" — worth retrying; "refused" — the API said no (see
 * `status`, and the message).
 */
export class SecureModeError extends Error {
  readonly reason: "unverified" | "unreachable" | "refused";
  readonly status: number;
  readonly code: string | null;
  constructor(reason: SecureModeError["reason"], message: string, status = 0, code: string | null = null) {
    super(message);
    this.name = "SecureModeError";
    this.reason = reason;
    this.status = status;
    this.code = code;
  }
}

type Verified = { publicKey: Uint8Array; goodUntil: number };

export class SecureMode {
  private info: SealedInfo | null = null;
  private verified: Verified | null = null;
  private verifying: Promise<Verified> | null = null;

  constructor(
    private readonly apiKey: string,
    private readonly baseUrl: string,
    private readonly doFetch: typeof globalThis.fetch,
    /** Pinned images. When set, these and only these are trusted, rather
     *  than the list the API publishes. */
    private readonly trustedImages?: string[],
  ) {}

  /** Where the enclave is, what it may be running, and which models. */
  async describe(): Promise<SealedInfo> {
    if (this.info) return this.info;
    let res: Response;
    try {
      res = await this.doFetch(`${this.baseUrl}/v1/sealed`);
    } catch (err) {
      throw new SecureModeError("unreachable", `Could not reach Secure AI: ${err instanceof Error ? err.message : "unknown"}`);
    }
    if (!res.ok) throw new SecureModeError("unreachable", `Secure AI answered ${res.status}.`, res.status);
    this.info = (await res.json()) as SealedInfo;
    return this.info;
  }

  /** The enclave's key, verified. Throws rather than returning something
   *  unverified: the consequence of a caller forgetting a check is the text. */
  private async key(): Promise<Verified> {
    if (this.verified && Date.now() < this.verified.goodUntil) return this.verified;
    if (!this.verifying) {
      this.verifying = this.verify().finally(() => { this.verifying = null; });
    }
    return this.verifying;
  }

  private async verify(): Promise<Verified> {
    const info = await this.describe();
    const trusted = (this.trustedImages ?? info.images).map((p) => p.toLowerCase());
    const nonce = `${Date.now()}-${crypto.randomUUID()}`;
    let body: { attested?: boolean; document?: string; reason?: string };
    try {
      const res = await this.doFetch(`${info.enclave.replace(/\/$/, "")}/attestation?nonce=${encodeURIComponent(nonce)}`);
      if (!res.ok) throw new Error(`status ${res.status}`);
      body = (await res.json()) as typeof body;
    } catch (err) {
      throw new SecureModeError("unreachable", `Could not reach the enclave: ${err instanceof Error ? err.message : "unknown"}`);
    }
    if (body.attested !== true || !body.document) {
      throw new SecureModeError("unverified", `The enclave is not attested: ${body.reason ?? "no document"}. Nothing was sent.`);
    }
    const result = await verifyAttestation(body.document, {
      nonce, trustedPCR0: trusted, rootFingerprint: NITRO_ROOT_SHA256,
    });
    if (!result.ok) throw new SecureModeError("unverified", `The enclave could not be verified: ${result.reason}. Nothing was sent.`);
    // Good for as long as the document is, less two minutes so a request
    // started just inside the window does not finish outside it.
    const goodUntil = Math.min(result.document.timestamp, Date.now()) + 3 * 60 * 60 * 1000 - 2 * 60 * 1000;
    this.verified = { publicKey: result.publicKey, goodUntil };
    return this.verified;
  }

  /** The provider request the enclave will make, minus the conversation. */
  private providerRequest(model: string, provider: string, maxTokens: number) {
    if (provider === "openai") {
      return { provider, path: "/v1/chat/completions", body: { model, stream: true, max_completion_tokens: maxTokens } };
    }
    if (provider === "google") {
      return { provider, path: `/v1beta/models/${model}:streamGenerateContent?alt=sse`, body: { generationConfig: { maxOutputTokens: maxTokens } } };
    }
    return { provider: "anthropic", path: "/v1/messages", body: { model, max_tokens: maxTokens, stream: true } };
  }

  async chat(opts: SecureChatOptions): Promise<string> {
    const info = await this.describe();
    if (!info.available) throw new SecureModeError("unreachable", "Secure mode is not available right now. Nothing was sent.", 503);
    const model = opts.model ?? info.default_model;
    const entry = info.models.find((m) => m.id === model);
    if (!entry) {
      throw new SecureModeError("refused", `Secure mode can't use "${model}". Use one of: ${info.models.map((m) => m.id).join(", ")}.`, 400, "model_not_available");
    }

    const enclave = await this.key();
    const picked = this.providerRequest(model, entry.provider, info.max_output_tokens);
    const { envelope, session } = await sealRequest(enclave.publicKey, JSON.stringify({
      ...picked,
      messages: opts.messages,
      ...(opts.system ? { system: opts.system } : {}),
    }));

    let res: Response;
    try {
      res = await this.doFetch(`${this.baseUrl}/v1/sealed/chat`, {
        method: "POST",
        headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json", "X-Model": model },
        body: JSON.stringify(envelope),
      });
    } catch (err) {
      throw new SecureModeError("unreachable", `Could not reach Secure AI: ${err instanceof Error ? err.message : "unknown"}`);
    }
    if (!res.ok || !res.body) {
      let message = `Secure AI refused this (${res.status}).`;
      let code: string | null = null;
      try {
        const e = ((await res.json()) as { error?: { message?: string; code?: string } }).error;
        if (e?.message) message = e.message;
        code = e?.code ?? null;
      } catch { /* the status is what there is */ }
      throw new SecureModeError("refused", message, res.status, code);
    }

    const reader = new SealedStreamReader(session);
    const stream = res.body.getReader();
    const decoder = new TextDecoder();
    let buffered = "";
    let text = "";
    for (;;) {
      const { value, done } = await stream.read();
      if (done) break;
      buffered += decoder.decode(value, { stream: true });
      const frames = buffered.split("\n\n");
      buffered = frames.pop() ?? "";
      for (const frame of frames) {
        const line = frame.trim();
        if (!line.startsWith("data:")) continue;
        const payload = line.slice(5).trim();
        if (!payload) continue;
        const piece = await reader.open(JSON.parse(payload) as SealedChunk);
        for (const delta of deltasFrom(piece, entry.provider)) {
          text += delta;
          opts.onText?.(delta);
        }
      }
    }
    // A stream that stopped without saying it was the last piece was cut
    // short somewhere in the middle. Silence is not an ending.
    reader.finish();
    return text;
  }
}

/** The text in one opened piece: the provider's own stream, real values back. */
export function deltasFrom(chunk: string, provider: string): string[] {
  const out: string[] = [];
  for (const line of chunk.split("\n")) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]") continue;
    try {
      const j = JSON.parse(payload) as {
        type?: string;
        delta?: { type?: string; text?: string };
        choices?: { delta?: { content?: string } }[];
        candidates?: { content?: { parts?: { text?: string }[] } }[];
      };
      let delta = "";
      if (provider === "anthropic") {
        if (j.type === "content_block_delta" && j.delta?.type === "text_delta" && j.delta.text) delta = j.delta.text;
      } else if (provider === "google") {
        delta = (j.candidates?.[0]?.content?.parts ?? []).map((p) => p.text ?? "").join("");
      } else {
        delta = j.choices?.[0]?.delta?.content ?? "";
      }
      if (delta) out.push(delta);
    } catch {
      /* partial or malformed: skipped */
    }
  }
  return out;
}
