import { describe, expect, it } from "vitest";
import { SecureAI, type LocalNameSwap } from "./index.js";

/** A stand-in for @secure-ai/names: swaps one known person. */
const names: LocalNameSwap = {
  async swap(text, map = {}) {
    const out = { ...map };
    if (text.includes("Maria Delgado")) out["Ingrid Novotny"] = "Maria Delgado";
    let swapped = text;
    for (const [fake, real] of Object.entries(out)) swapped = swapped.split(real).join(fake);
    return { text: swapped, map: out };
  },
};

function client() {
  const bodies: string[] = [];
  const fetch = (async (_url: string, init: RequestInit) => {
    const body = String(init.body);
    bodies.push(body);
    const sent = JSON.parse(body) as { text: string };
    return new Response(JSON.stringify({ text: sent.text.replace("sarah@acme.co", "[EMAIL_1]"), map: { "[EMAIL_1]": "sarah@acme.co" } }), { status: 200 });
  }) as typeof globalThis.fetch;
  return { sai: new SecureAI({ apiKey: "sk_test", fetch, names }), bodies };
}

describe("names found on this machine", () => {
  it("never sends the real name, and returns one map for restoring", async () => {
    const { sai, bodies } = client();
    const r = await sai.redact("Email Maria Delgado at sarah@acme.co");
    expect(bodies[0]).not.toContain("Maria Delgado");
    expect(r.text).toBe("Email Ingrid Novotny at [EMAIL_1]");
    expect(r.map).toEqual({ "[EMAIL_1]": "sarah@acme.co", "Ingrid Novotny": "Maria Delgado" });
    expect(sai.restoreLocal("Hi Ingrid Novotny, [EMAIL_1]", r.map)).toBe("Hi Maria Delgado, sarah@acme.co");
  });

  it("keeps a local name out of the map passed back on the next turn", async () => {
    const { sai, bodies } = client();
    const first = await sai.redact("Email Maria Delgado");
    await sai.redact("And Maria Delgado again", { map: first.map });
    expect(bodies[1]).not.toContain("Maria Delgado");
    expect(JSON.parse(bodies[1]).text).toBe("And Ingrid Novotny again");
  });
});
