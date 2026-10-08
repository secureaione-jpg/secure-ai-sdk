import { beforeEach, describe, expect, it, vi } from "vitest";

import { openRequest, sealChunk } from "./sealed/envelope.js";

/**
 * Secure mode in the SDK, with the enclave played by a keypair we hold.
 *
 * The verifier is replaced here so a test can produce a document that
 * passes; secureRefusal.test.ts runs the real one against a real document and
 * pins the part that matters more — that a document which does not check out
 * means nothing is sent.
 */

const verify = vi.hoisted(() => ({ result: null as unknown }));
vi.mock("./sealed/attestation.js", () => ({
  NITRO_ROOT_SHA256: "root",
  verifyAttestation: vi.fn(async () => verify.result),
}));

import { SecureAI, SecureModeError } from "./index.js";

const INFO = {
  object: "sealed", available: true, enclave: "https://enclave.test",
  images: ["aa"], models: [{ id: "claude-sonnet-5-5", provider: "anthropic" }, { id: "gpt-6", provider: "openai" }],
  default_model: "claude-sonnet-5-5", max_output_tokens: 4096,
};

let pair: CryptoKeyPair;
let asked: Array<{ url: string; init?: RequestInit }>;
let opened: Record<string, unknown> | null;
let answer: (s: CryptoKey) => Promise<string>;

const frame = async (s: CryptoKey, i: number, text: string, final: boolean) =>
  `data: ${JSON.stringify(await sealChunk(s, i, text, final))}\n\n`;

const sse = (...events: unknown[]) => events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join("");

beforeEach(async () => {
  pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  verify.result = { ok: true, publicKey: spki, pcr0: "aa", document: { timestamp: Date.now() } };
  asked = [];
  opened = null;
  answer = async (s) =>
    (await frame(s, 0, sse({ type: "content_block_delta", delta: { type: "text_delta", text: "Dear Sara" } }), false)) +
    (await frame(s, 1, sse({ type: "message_stop" }), true));
});

const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = String(input);
  asked.push({ url, init });
  if (url.endsWith("/v1/sealed")) return Response.json(INFO);
  if (url.startsWith("https://enclave.test/attestation")) return Response.json({ attested: true, document: "doc" });
  if (url.endsWith("/v1/sealed/chat")) {
    const { body, session } = await openRequest(JSON.parse(String(init?.body)), async (ct) =>
      new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, pair.privateKey, ct.slice().buffer)));
    opened = JSON.parse(body);
    return new Response(await answer(session), { status: 200, headers: { "Content-Type": "text/event-stream" } });
  }
  return new Response("{}", { status: 404 });
}) as typeof fetch;

const client = () => new SecureAI({ apiKey: "sai_test", baseUrl: "https://secureai.one", fetch: fetchImpl });

describe("secureChat", () => {
  it("seals the conversation, and reads the sealed answer", async () => {
    const pieces: string[] = [];
    const text = await client().secureChat({
      messages: [{ role: "user", content: "Write to Sara Whitfield" }],
      system: "Be brief.",
      onText: (p) => pieces.push(p),
    });
    expect(text).toBe("Dear Sara");
    expect(pieces).toEqual(["Dear Sara"]);
    expect(opened).toMatchObject({
      provider: "anthropic", path: "/v1/messages",
      body: { model: "claude-sonnet-5-5", max_tokens: 4096, stream: true },
      messages: [{ role: "user", content: "Write to Sara Whitfield" }],
      system: "Be brief.",
    });
  });

  it("never puts the conversation on the wire in the clear", async () => {
    await client().secureChat({ messages: [{ role: "user", content: "Write to Sara Whitfield" }] });
    const sent = asked.find((a) => a.url.endsWith("/v1/sealed/chat"))!;
    expect(String(sent.init?.body)).not.toContain("Sara");
    expect(new Headers(sent.init?.headers).get("X-Model")).toBe("claude-sonnet-5-5");
    expect(new Headers(sent.init?.headers).get("Authorization")).toBe("Bearer sai_test");
  });

  it("asks an OpenAI model in OpenAI's shape and reads its stream", async () => {
    answer = async (s) => frame(s, 0, sse({ choices: [{ delta: { content: "Hi" } }] }) + "data: [DONE]\n\n", true);
    expect(await client().secureChat({ model: "gpt-6", messages: [{ role: "user", content: "x" }] })).toBe("Hi");
    expect(opened).toMatchObject({ provider: "openai", path: "/v1/chat/completions", body: { max_completion_tokens: 4096 } });
  });

  it("refuses an answer that was cut short", async () => {
    answer = async (s) => frame(s, 0, sse({ type: "content_block_delta", delta: { type: "text_delta", text: "Dear" } }), false);
    await expect(client().secureChat({ messages: [{ role: "user", content: "x" }] })).rejects.toThrow(/final/);
  });

  it("sends nothing when the enclave cannot be verified", async () => {
    verify.result = { ok: false, reason: "untrusted image" };
    const err = await client().secureChat({ messages: [{ role: "user", content: "x" }] }).catch((e) => e);
    expect(err).toBeInstanceOf(SecureModeError);
    expect(err.reason).toBe("unverified");
    expect(asked.some((a) => a.url.endsWith("/v1/sealed/chat"))).toBe(false);
  });

  it("refuses a model the enclave does not offer, before sealing anything", async () => {
    const err = await client().secureChat({ model: "secureai-auto", messages: [{ role: "user", content: "x" }] }).catch((e) => e);
    expect(err.code).toBe("model_not_available");
    expect(asked.some((a) => a.url.includes("/attestation"))).toBe(false);
  });

  it("verifies once, not on every message", async () => {
    const sai = client();
    await sai.secureChat({ messages: [{ role: "user", content: "a" }] });
    await sai.secureChat({ messages: [{ role: "user", content: "b" }] });
    expect(asked.filter((a) => a.url.includes("/attestation"))).toHaveLength(1);
  });
});
