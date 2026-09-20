# @secure-ai/guard

Data loss prevention for AI agents. Put a check in front of every action an
agent takes, before it takes it.

```bash
npm install @secure-ai/guard
```

## The one thing worth knowing

`guard` wraps a function an agent already calls, and calls it with the
**rewritten** arguments:

```ts
import { SecureAI } from "@secure-ai/guard";

const sai = new SecureAI({ apiKey: process.env.SECURE_AI_KEY!, agent: "support-bot" });

const sendEmail = sai.guard("email.send", async (input: { to: string; body: string }) => {
  return mailer.send(input);
});

await sendEmail({ to: "ana@clientfirm.com", body: "About invoice 4471…" });
```

The agent wrote a real address. `mailer.send` receives a stand-in. Nothing in
the agent's code had to check a decision, which is the point — protection that
depends on remembering to check it is protection that ends at the fourteenth
call site.

If the policy refuses the action, the wrapped function is never called and
`ActionBlocked` is thrown.

## Getting the real values back

Redaction is reversible with the map the inspection returned. The map is
returned to you and **is not stored on our side** — losing it means losing the
ability to restore that reply.

```ts
const verdict = await sai.inspect({ tool: "llm.complete", input: prompt });
const reply = await model.complete(verdict.input);
const readable = await sai.restore(reply, verdict.map);
```

## Rules

Rules live on the account, not in the request. An agent cannot argue with them.

```ts
await sai.setPolicy({
  fallback: "redact",
  rules: [
    { kind: "secret", decision: "block" },
    { kind: "card", decision: "block", direction: "outbound" },
    { kind: "email", decision: "allow", tools: ["crm.*"] },
  ],
  denyTools: ["shell.*"],
});
```

`decision` is `allow`, `redact` or `block`. When an action contains several
findings, the **most severe** decision wins — an action carrying a credential
is refused even if everything else in it was fine.

When the scanner keeps flagging something that is yours:

```ts
await sai.allowValue("@ourcompany.com");
```

That applies to every agent on the account from the next action onward.

## The trail

```ts
const { blocked, byKind } = await sai.summary();
const { events } = await sai.audit({ limit: 100 });
```

Records hold the **kind and location** of what was found — `card` at
`body.payment.number` — and never the value. There is no field on an audit
record that can hold one. That is deliberate: a store of every sensitive value
every agent touched is the thing this product exists to avoid being.

## When Secure AI is unreachable

The default is `onUnreachable: "closed"` — the action does not happen, and the
error propagates. That is the correct default for a security control, and it
does mean an outage here stops agents.

```ts
new SecureAI({ apiKey, onUnreachable: "open" }); // availability over control
```

Failing open never lets a real refusal through: a 401, 402 or quota error is an
answer, not an outage, and still throws.

## No code to change at all

If wrapping each tool is too invasive, hand the gateway fetch to whatever HTTP
client the agent already uses. Every request it makes is inspected on the way
out, and no call site changes:

```ts
const openai = new OpenAI({
  apiKey: process.env.OPENAI_KEY!,
  fetch: sai.fetch({ forwardAuth: `Bearer ${process.env.OPENAI_KEY}` }),
});
```

Two credentials travel and they are kept apart on purpose: your Secure AI key
authenticates you to us and is **never** forwarded; `forwardAuth` is the
destination's own credential and becomes its `Authorization` header.

A refused request throws `ActionBlocked`, the same as a guarded function.
Pass `throwOnBlock: false` to get the 403 back instead.

The gateway will not forward to private or link-local addresses, so it cannot
be pointed at a cloud metadata service. Bodies it cannot read as text — an
image, a zip — are forwarded and the response carries
`X-Secure-AI-Inspected: false`, rather than a clean log implying a check that
did not happen.

## Runtime

Needs `fetch` and nothing else — Node 18+, Bun, Deno, Cloudflare Workers,
browsers. No dependencies, deliberately: this runs next to somebody's model
client and framework, and every dependency it adds is a version conflict it can
cause in a process already carrying too many.

## Also available over MCP

Agents that speak MCP can reach the same controls as tools at
`https://secureai.one/mcp` — `inspect_action`, `check_policy`,
`recent_activity`, plus `redact` and `restore`.

Full reference: <https://secureai.one/developers>
