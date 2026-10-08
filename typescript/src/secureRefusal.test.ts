import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { SecureAI, SecureModeError } from "./index.js";

/**
 * The real verifier, a real document, and the answer that matters: when the
 * enclave's proof does not check out, the conversation is not sent.
 *
 * The fixture is the attestation document the web app's verifier is tested
 * against, signed by a Nitro Security Module. Its nonce is fixed, so it can
 * never verify against the fresh nonce a client sends — which is exactly a
 * replayed document, the case this pins.
 */

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "__fixtures__/attestation-enclave-v8.json"), "utf8"),
) as { attested: boolean; document: string };

describe("Secure mode refuses", () => {
  it("a replayed document: nothing reaches /v1/sealed/chat", async () => {
    const asked: string[] = [];
    const sai = new SecureAI({
      apiKey: "sai_test",
      fetch: (async (input: string | URL | Request) => {
        const url = String(input);
        asked.push(url);
        if (url.endsWith("/v1/sealed")) {
          return Response.json({
            available: true, enclave: "https://enclave.test", images: ["00"],
            models: [{ id: "claude-sonnet-5-5", provider: "anthropic" }], default_model: "claude-sonnet-5-5", max_output_tokens: 4096,
          });
        }
        if (url.includes("/attestation")) return Response.json(fixture);
        throw new Error(`should not have been asked for ${url}`);
      }) as typeof fetch,
    });

    const err = await sai.secureChat({ messages: [{ role: "user", content: "Sara Whitfield" }] }).catch((e) => e);
    expect(err).toBeInstanceOf(SecureModeError);
    expect(err.reason).toBe("unverified");
    expect(asked.some((u) => u.endsWith("/v1/sealed/chat"))).toBe(false);
  });
});
