import { describe, expect, it, vi } from "vitest";

import { ActionBlocked, ApprovalRefused, SecureAI, SecureAIError } from "./index";

/**
 * The SDK, and the one behaviour worth most of these tests.
 *
 * `guard` calls the wrapped function with the *rewritten* input, not the
 * caller's. That is what makes protection automatic rather than opt-in, and
 * it is the thing a refactor could quietly undo — the tests would still pass
 * if guard merely returned a decision, unless one of them checks what the
 * underlying function actually received.
 */

type Handler = (url: string, init: RequestInit) => { status?: number; body: unknown };

function client(handler: Handler, opts: Partial<ConstructorParameters<typeof SecureAI>[0]> = {}) {
  const calls: Array<{ url: string; body: unknown }> = [];
  const fetchImpl = (async (url: string | URL | Request, init: RequestInit = {}) => {
    const u = String(url);
    calls.push({ url: u, body: init.body ? JSON.parse(String(init.body)) : undefined });
    const { status = 200, body } = handler(u, init);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;

  return {
    calls,
    sai: new SecureAI({ apiKey: "sai_test", baseUrl: "https://api.test", fetch: fetchImpl, ...opts }),
  };
}

const allowed = (input: unknown) => ({
  body: { decision: "allow", input, map: {}, findings: [], toolDenied: false, policySource: "default", auditId: "a1" },
});
const redacted = (input: unknown, map: Record<string, string>) => ({
  body: { decision: "redact", input, map, findings: [], toolDenied: false, policySource: "account", auditId: "a2" },
});
const blocked = (findings: unknown[] = [{ kind: "secret", path: "headers.authorization", decision: "block" }]) => ({
  body: { decision: "block", map: {}, findings, toolDenied: false, policySource: "account", auditId: "a3" },
});

describe("construction", () => {
  it("insists on a key", () => {
    expect(() => new SecureAI({ apiKey: "" })).toThrow(/apiKey/);
  });

  it("trims a trailing slash off the base url rather than doubling it", async () => {
    const { calls, sai } = client(() => allowed({}), { baseUrl: "https://api.test/" });
    await sai.inspect({ tool: "t", input: {} });
    expect(calls[0].url).toBe("https://api.test/v1/inspect");
  });
});

describe("inspect", () => {
  it("sends the action and defaults the direction to outbound", async () => {
    const { calls, sai } = client(() => allowed({ a: 1 }));
    await sai.inspect({ tool: "http.post", input: { a: 1 } });
    expect(calls[0].body).toMatchObject({ tool: "http.post", input: { a: 1 }, direction: "outbound" });
  });

  it("names the agent from the client when the call does not", async () => {
    const { calls, sai } = client(() => allowed({}), { agent: "nightly-sync" });
    await sai.inspect({ tool: "t", input: {} });
    expect((calls[0].body as { agent: string }).agent).toBe("nightly-sync");
  });

  it("turns an API refusal into a SecureAIError carrying the code", async () => {
    const { sai } = client(() => ({
      status: 402,
      body: { error: { message: "This account does not have API access.", code: "api_access_required" } },
    }));
    await expect(sai.inspect({ tool: "t", input: {} })).rejects.toMatchObject({
      name: "SecureAIError",
      status: 402,
      code: "api_access_required",
    });
  });

  it("does not choke on a non-JSON body from something in front of the API", async () => {
    const fetchImpl = (async () => new Response("<html>502</html>", { status: 502 })) as unknown as typeof globalThis.fetch;
    const sai = new SecureAI({ apiKey: "sai_test", fetch: fetchImpl });
    await expect(sai.inspect({ tool: "t", input: {} })).rejects.toBeInstanceOf(SecureAIError);
  });
});

describe("guard", () => {
  /* The whole mechanism. If this ever passes while the wrapped function
     receives the caller's original input, the library protects nothing. */
  it("calls the wrapped function with the rewritten input, not the caller's", async () => {
    const real = { to: "ana@example.org" };
    const safe = { to: "person1@example.com" };
    const { sai } = client(() => redacted(safe, { "person1@example.com": "ana@example.org" }));

    const send = vi.fn(async (input: { to: string }) => `sent to ${input.to}`);
    const guarded = sai.guard("email.send", send);
    const out = await guarded(real);

    expect(send).toHaveBeenCalledWith(safe);
    expect(send).not.toHaveBeenCalledWith(real);
    expect(out).toBe("sent to person1@example.com");
  });

  it("throws rather than returning when the policy refuses, and never calls the function", async () => {
    const { sai } = client(() => blocked());
    const send = vi.fn(async () => "sent");
    const guarded = sai.guard("http.post", send);

    await expect(guarded({ headers: { authorization: "sk-live" } })).rejects.toBeInstanceOf(ActionBlocked);
    expect(send).not.toHaveBeenCalled();
  });

  it("says what was refused, in the message", async () => {
    const { sai } = client(() => blocked());
    await expect(sai.guard("http.post", async () => "x")({})).rejects.toThrow(
      /refused http\.post: secret at headers\.authorization/,
    );
  });

  it("explains a denied tool differently from denied contents", async () => {
    const { sai } = client(() => ({
      body: { decision: "block", map: {}, findings: [], toolDenied: true, policySource: "account", auditId: "a4" },
    }));
    await expect(sai.guard("shell.exec", async () => "x")({})).rejects.toThrow(
      /the tool itself is not permitted/,
    );
  });

  it("passes an allowed action through untouched", async () => {
    const input = { q: "orders shipped yesterday" };
    const { sai } = client(() => allowed(input));
    const run = vi.fn(async (i: typeof input) => i.q);
    expect(await sai.guard("db.query", run)(input)).toBe("orders shipped yesterday");
    expect(run).toHaveBeenCalledWith(input);
  });
});

describe("when Secure AI cannot be reached", () => {
  const dead = (async () => { throw new TypeError("network down"); }) as unknown as typeof globalThis.fetch;

  /* The correct default for a security control, and it does mean an outage
     here stops agents — which is why the other option exists and is named. */
  it("fails closed by default: the action does not happen", async () => {
    const sai = new SecureAI({ apiKey: "sai_test", fetch: dead });
    const run = vi.fn(async () => "done");
    await expect(sai.guard("t", run)({})).rejects.toThrow(/network down/);
    expect(run).not.toHaveBeenCalled();
  });

  it("fails open when asked to, and the action happens unchecked", async () => {
    const sai = new SecureAI({ apiKey: "sai_test", fetch: dead, onUnreachable: "open" });
    const run = vi.fn(async () => "done");
    expect(await sai.guard("t", run)({})).toBe("done");
    expect(run).toHaveBeenCalled();
  });

  /* An outage is not a refusal. Failing open must never let a 402 or a
     revoked key through as though the network had blinked. */
  it("still refuses when the API answered, even with onUnreachable open", async () => {
    const { sai } = client(() => ({ status: 401, body: { error: { message: "Invalid API key.", code: "invalid_api_key" } } }), {
      onUnreachable: "open",
    });
    const run = vi.fn(async () => "done");
    await expect(sai.guard("t", run)({})).rejects.toBeInstanceOf(SecureAIError);
    expect(run).not.toHaveBeenCalled();
  });
});

describe("policy and trail", () => {
  it("reads and replaces the policy", async () => {
    const { calls, sai } = client((url, init) =>
      init.method === "PUT"
        ? { body: { policy: { version: 1, fallback: "block", rules: [] } } }
        : { body: { policy: { version: 1, fallback: "redact", rules: [] }, source: "default" } },
    );
    expect(await sai.getPolicy()).toMatchObject({ source: "default" });
    await sai.setPolicy({ fallback: "block", rules: [] });
    expect(calls[1].body).toMatchObject({ policy: { fallback: "block" } });
  });

  it("exempts a value", async () => {
    const { calls, sai } = client(() => ({ body: { policy: { version: 1, fallback: "redact", rules: [], allow: ["@ours.com"] }, added: "@ours.com" } }));
    await sai.allowValue("@ours.com");
    expect(calls[0].url).toBe("https://api.test/v1/policy/allow");
    expect(calls[0].body).toEqual({ value: "@ours.com" });
  });

  it("passes paging through on the query string", async () => {
    const { calls, sai } = client(() => ({ body: { events: [], cursor: null } }));
    await sai.audit({ limit: 10, cursor: "abc" });
    expect(calls[0].url).toBe("https://api.test/v1/audit?limit=10&cursor=abc");
  });

  it("asks for the summary without a query string when unpaged", async () => {
    const { calls, sai } = client(() => ({ body: { window: 0, actions: 0, blocked: 0, redacted: 0, allowed: 0, byKind: [], byTool: [] } }));
    await sai.summary();
    expect(calls[0].url).toBe("https://api.test/v1/audit/summary");
  });

  it("restores a reply from the map", async () => {
    const { calls, sai } = client(() => ({ body: { text: "call ana@example.org" } }));
    const out = await sai.restore("call person1@example.com", { "person1@example.com": "ana@example.org" });
    expect(out).toBe("call ana@example.org");
    expect(calls[0].url).toBe("https://api.test/v1/restore");
  });
});

describe("fetch — the gateway integration", () => {
  it("sends the destination as a header and calls the gateway", async () => {
    const { calls, sai } = client(() => ({ body: { ok: true } }));
    const f = sai.fetch();
    await f("https://api.vendor.com/v1/send", { method: "POST", body: "{}" });
    expect(calls[0].url).toBe("https://api.test/v1/gateway");
  });

  /* Two credentials travel and confusing them would be a breach: ours proves
     who is calling Secure AI, theirs is for the destination. */
  it("keeps our key and the vendor's key apart", async () => {
    let seen: Headers | null = null;
    const fetchImpl = (async (_u: string, init: RequestInit = {}) => {
      seen = new Headers(init.headers);
      return new Response("{}", { status: 200 });
    }) as unknown as typeof globalThis.fetch;
    const sai = new SecureAI({ apiKey: "sai_ours", baseUrl: "https://api.test", fetch: fetchImpl });

    await sai.fetch({ forwardAuth: "Bearer sk-theirs" })("https://api.vendor.com/x");
    expect(seen!.get("authorization")).toBe("Bearer sai_ours");
    expect(seen!.get("x-secure-ai-forward-authorization")).toBe("Bearer sk-theirs");
    expect(seen!.get("x-secure-ai-target")).toBe("https://api.vendor.com/x");
  });

  it("names the agent so its requests group in the trail", async () => {
    let seen: Headers | null = null;
    const fetchImpl = (async (_u: string, init: RequestInit = {}) => {
      seen = new Headers(init.headers);
      return new Response("{}", { status: 200 });
    }) as unknown as typeof globalThis.fetch;
    const sai = new SecureAI({ apiKey: "sai_x", baseUrl: "https://api.test", fetch: fetchImpl, agent: "nightly" });
    await sai.fetch()("https://api.vendor.com/x");
    expect(seen!.get("x-secure-ai-agent")).toBe("nightly");
  });

  it("throws on a refusal, so it fails like a guarded function", async () => {
    const { sai } = client(() => ({
      status: 403,
      body: { error: { code: "blocked_by_policy", message: "refused" } },
    }));
    await expect(sai.fetch()("https://api.vendor.com/x")).rejects.toBeInstanceOf(ActionBlocked);
  });

  it("hands back the response instead when asked to", async () => {
    const { sai } = client(() => ({
      status: 403,
      body: { error: { code: "blocked_by_policy", message: "refused" } },
    }));
    const res = await sai.fetch({ throwOnBlock: false })("https://api.vendor.com/x");
    expect(res.status).toBe(403);
  });

  /* A 403 from the destination itself is the destination's answer and must
     not be reported as our refusal. */
  it("does not mistake the destination's own 403 for a policy block", async () => {
    const { sai } = client(() => ({ status: 403, body: { error: { message: "vendor says no" } } }));
    const res = await sai.fetch()("https://api.vendor.com/x");
    expect(res.status).toBe(403);
  });
});

describe("actions held for a person", () => {
  const held = (approvalId = "ap-1") => ({
    body: {
      decision: "approve", approvalId, expiresAt: Date.now() + 60_000,
      map: {}, findings: [], toolDenied: false, policySource: "account", auditId: "a9",
    },
  });
  const approvalBody = (status: string, note?: string) => ({
    body: {
      approval: {
        id: "ap-1", createdAt: Date.now(), expiresAt: Date.now() + 60_000,
        status, agent: null, tool: "refund.issue", keyId: "k1", findings: [],
        ...(note ? { note } : {}),
      },
    },
  });

  it("waits, then sends the action once a person says yes", async () => {
    let inspects = 0;
    const { sai } = client((url) => {
      if (url.endsWith("/v1/inspect")) {
        inspects += 1;
        // First ask is held; the second carries the approval id.
        return inspects === 1
          ? held()
          : { body: { decision: "allow", input: { card: "real" }, map: {}, findings: [], toolDenied: false, policySource: "account", auditId: "a10" } };
      }
      return approvalBody("approved");
    });

    const run = vi.fn(async (i: { card: string }) => `sent ${i.card}`);
    const out = await sai.guard("refund.issue", run, { pollMs: 250 })({ card: "real" });

    expect(out).toBe("sent real");
    expect(run).toHaveBeenCalledTimes(1);
    expect(inspects).toBe(2);
  });

  it("comes back with the approval id, so a yes cannot be spent elsewhere", async () => {
    /* A counter, not calls.length — the helper records a call before the
       handler runs, so counting from inside it is always one ahead. */
    let inspects = 0;
    const { calls, sai } = client((url) => {
      if (url.endsWith("/v1/inspect")) {
        inspects += 1;
        return inspects === 1
          ? held()
          : { body: { decision: "allow", input: {}, map: {}, findings: [], toolDenied: false, policySource: "account", auditId: "a" } };
      }
      return approvalBody("approved");
    });
    await sai.guard("refund.issue", async () => "ok", { pollMs: 250 })({});
    const second = calls.filter((c) => c.url.endsWith("/v1/inspect"))[1].body as Record<string, unknown>;
    expect(second.approvalId).toBe("ap-1");
  });

  /* A refusal by a person is a conversation, not a rule to change — so it
     must not arrive as ActionBlocked. */
  it("raises a different error when a person says no", async () => {
    const { sai } = client((url) =>
      url.endsWith("/v1/inspect") ? held() : approvalBody("denied", "not this one"));
    const run = vi.fn();
    await expect(sai.guard("refund.issue", run, { pollMs: 250 })({}))
      .rejects.toBeInstanceOf(ApprovalRefused);
    expect(run).not.toHaveBeenCalled();
  });

  it("says so when nobody answered in time", async () => {
    const { sai } = client((url) =>
      url.endsWith("/v1/inspect") ? held() : approvalBody("expired"));
    await expect(sai.guard("refund.issue", async () => "x", { pollMs: 250 })({}))
      .rejects.toThrow(/nobody answered/);
  });

  it("can refuse to wait, for callers that would rather handle it", async () => {
    const { sai } = client(() => held());
    await expect(
      sai.guard("refund.issue", async () => "x", { waitForApproval: false })({}),
    ).rejects.toMatchObject({ name: "ApprovalRefused", status: "pending" });
  });

  it("lists what is waiting", async () => {
    const { calls, sai } = client(() => ({ body: { approvals: [] } }));
    await sai.approvals({ status: "pending", limit: 20 });
    expect(calls[0].url).toBe("https://api.test/v1/approvals?status=pending&limit=20");
  });
});

/*
 * What happens when the answer is malformed.
 *
 * The API omits "input" only on a block, so on a redact it is always there —
 * until some day it is not. guard used to fall back to the caller's own
 * input in that case, which on a redact is the one thing that must not go:
 * it still holds the values the decision had just said to replace. A missing
 * field turned into the library doing the exact opposite of its purpose,
 * silently, with the trail recording a redaction that never happened.
 */
describe("a redact with nothing to send", () => {
  it("throws rather than sending the caller's own data", async () => {
    const { sai } = client(() => ({
      body: {
        decision: "redact", map: {}, findings: [],
        toolDenied: false, policySource: "account", auditId: "a9",
      },
    }));
    const send = vi.fn(async () => "sent");
    await expect(sai.guard("email.send", send)({ to: "ana@clientfirm.com" }))
      .rejects.toThrow(/nothing to send/);
    // The point of the test: the wrapped function never ran.
    expect(send).not.toHaveBeenCalled();
  });

  it("names it as ours rather than as a network failure", async () => {
    const { sai } = client(() => ({
      body: {
        decision: "redact", map: {}, findings: [],
        toolDenied: false, policySource: "account", auditId: "a9",
      },
    }));
    await expect(sai.guard("email.send", async () => "x")({ a: 1 }))
      .rejects.toBeInstanceOf(SecureAIError);
  });

  /* An allow is the opposite case: nothing was rewritten, so the caller's
     own input is the correct thing to pass and the fallback belongs there. */
  it("still passes the original through on an allow", async () => {
    const { sai } = client(() => ({
      body: {
        decision: "allow", map: {}, findings: [],
        toolDenied: false, policySource: "default", auditId: "a10",
      },
    }));
    const send = vi.fn(async (x: unknown) => x);
    const original = { note: "nothing sensitive" };
    await expect(sai.guard("mail.send", send)(original)).resolves.toEqual(original);
    expect(send).toHaveBeenCalledWith(original);
  });

  /*
   * A decision this version has never heard of.
   *
   * Only allow and redact mean "this may go". The check used to be the other
   * way round — refuse on block, refuse on approve, send otherwise — which
   * is how "approve" itself got sent when it was introduced: the client
   * compared against "block", saw no match, and called through.
   *
   * A policy gains a decision, an agent keeps an older client, and the
   * failure has to be a refusal rather than a send.
   */
  it("refuses a decision it does not recognise rather than sending", async () => {
    const { sai } = client(() => ({
      body: {
        decision: "quarantine", map: {}, findings: [],
        toolDenied: false, policySource: "default", auditId: "a11",
      },
    }));
    const send = vi.fn(async (x: unknown) => x);

    await expect(sai.guard("mail.send", send)({ note: "hello" })).rejects.toThrow(
      /does not know how to send safely/,
    );
    expect(send).not.toHaveBeenCalled();
  });

  it("names the unknown decision, so the log says which one", async () => {
    const { sai } = client(() => ({
      body: {
        decision: "quarantine", map: {}, findings: [],
        toolDenied: false, policySource: "default", auditId: "a12",
      },
    }));

    await expect(
      sai.guard("mail.send", async (x: unknown) => x)({ note: "hello" }),
    ).rejects.toMatchObject({ code: "unknown_decision", message: /"quarantine"/ });
  });

  /* The same guard on the second inspect, the one made after a person says
     yes. That call is the last thing between an approval and the action. */
  /*
   * An approval with no expiry on it.
   *
   * waitForApproval stops when now is past expiresAt, and `Date.now() >=
   * undefined` is a NaN comparison, so it is false and the loop does not
   * stop. Nothing throws and nothing hangs visibly: a guarded call polls a
   * metered API every two seconds for as long as the process lives. The
   * Python client already coerced this and this one did not.
   *
   * vi.useFakeTimers is what makes the difference testable at all — under
   * real timers a regression here does not fail, it runs until the suite
   * is killed.
   */
  it("treats an approval with no expiry as expired instead of polling forever", async () => {
    vi.useFakeTimers();
    try {
      let polls = 0;
      const { sai } = client((url) => {
        if (url.includes("/v1/approvals/")) {
          polls += 1;
          return { body: { approval: { id: "ap_1", status: "pending", tool: "mail.send" } } };
        }
        return {
          body: {
            decision: "approve", approvalId: "ap_1", findings: [],
            toolDenied: false, policySource: "default", auditId: "a15",
          },
        };
      });
      const send = vi.fn(async (x: unknown) => x);

      const ran = sai.guard("mail.send", send, { pollMs: 1 })({ note: "hi" });
      const settled = expect(ran).rejects.toBeInstanceOf(ApprovalRefused);
      await vi.advanceTimersByTimeAsync(50);
      await settled;

      expect(send).not.toHaveBeenCalled();
      // One look, then the missing expiry decides it. Not a loop.
      expect(polls).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses an unknown decision on the re-check after an approval", async () => {
    let inspects = 0;
    const { sai } = client((url) => {
      if (url.endsWith("/v1/inspect")) {
        inspects += 1;
        return inspects === 1
          ? {
              body: {
                decision: "approve", approvalId: "ap_1", findings: [],
                toolDenied: false, policySource: "default", auditId: "a13",
              },
            }
          : {
              body: {
                decision: "quarantine", map: {}, findings: [],
                toolDenied: false, policySource: "default", auditId: "a14",
              },
            };
      }
      return { body: { approval: { id: "ap_1", status: "approved", tool: "mail.send" } } };
    });
    const send = vi.fn(async (x: unknown) => x);

    await expect(
      sai.guard("mail.send", send, { pollMs: 1 })({ note: "hello" }),
    ).rejects.toThrow(/does not know how to send safely/);
    expect(send).not.toHaveBeenCalled();
  });
});

describe("the README says the version that is published", () => {
  /*
   * The table's "Both are x.y.z" line drifted twice — it said 0.2.1 while
   * npm and PyPI were on 0.2.3. It is the first thing on the repository
   * page, so it is what somebody checks before deciding whether to upgrade,
   * and a stale number there tells them not to bother.
   *
   * Both packages are released together and share a number, so one
   * assertion covers both.
   */
  it("matches package.json", async () => {
    const { readFileSync } = await import("node:fs");
    const { dirname, join } = await import("node:path");
    const { fileURLToPath } = await import("node:url");

    // Anchored to this file, not to the working directory: CI runs the suite
    // from typescript/ and a developer may run it from the repo root.
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(
      readFileSync(join(here, "..", "package.json"), "utf8"),
    ) as { version: string };
    const readme = readFileSync(join(here, "..", "..", "README.md"), "utf8");

    const claimed = readme.match(/Both are (\d+\.\d+\.\d+)\./);
    expect(claimed, "the README no longer states a version in the expected shape").not.toBeNull();
    expect(claimed![1]).toBe(pkg.version);
  });
});
