# Secure AI SDKs

Client libraries for [Secure AI](https://secureai.one) — data loss prevention
for AI agents.

An agent reads a customer record and passes it to a tool. Nobody typed it, so
nothing that watches what people type ever sees it go. These libraries put a
check in front of the action instead: the agent says what it is about to do,
and gets back a decision before it does it.

| | Install | Status |
|---|---|---|
| [TypeScript](typescript) | `npm install @secure-ai/guard` | Not yet published |
| [Python](python) | `pip install secure-ai-guard` | Not yet published |

Both are version 0.1.0 and neither is on a registry yet. Until they are, use
the API directly — or the gateway or MCP endpoint below, which need no client
library at all.

## The one thing worth knowing

`guard` wraps a function your agent already calls, and calls it with the
**rewritten** arguments:

```ts
const sendEmail = sai.guard("email.send", mailer.send);

await sendEmail({ to: "ana@clientfirm.com", body: draft });
// mailer.send receives a stand-in. A refusal throws.
```

The agent wrote a real address; the tool receives a substitute. Nothing in the
agent's code has to remember to check a decision — protection that depends on
being remembered ends at the fourteenth call site.

## Four answers, not three

Every check returns one of:

- **allow** — nothing regulated in it; the action proceeds
- **redact** — sensitive values swapped for stand-ins; use the rewritten input
- **approve** — a person has to look; the action waits, and is answered in the
  dashboard. Do not retry it in a loop
- **block** — it does not go, and nothing sendable comes back

## If you would rather not install anything

Neither of these needs a client library:

- **Gateway** — `POST https://secureai.one/v1/gateway` with the destination in
  an `X-Secure-AI-Target: https://api.vendor.com/…` header. Point an HTTP
  client at it and every request through it is checked. No code to change.

  The destination also goes after `/v1/gateway/` in the path, but only
  against the Worker host directly —
  `secure-ai-worker.secureai-one.workers.dev`. On `secureai.one` the proxy
  in front normalises `//` in a path and answers `308` to
  `…/gateway/https:/api.vendor.com/…`, one slash, which the gateway then
  refuses as a destination. The header form has no such problem and is the
  one to reach for.
- **MCP** — `https://secureai.one/mcp`. Hand an assistant the URL and it
  gets `redact`, `restore`, `inspect_action`, `check_policy` and
  `recent_activity` as tools it can call.

## What the audit trail holds

The kind and location of what was found — `card at body.payment.number` — and
never the value. There is no field on the record that can hold one, which is
checkable by reading the type rather than by trusting this sentence. Not a
hash of one either: the space of card numbers and phone numbers is small
enough to enumerate, so a hash of one is the value with extra steps.

## Documentation

[secureai.one/developers](https://secureai.one/developers)

## Licence

MIT — see [LICENSE](LICENSE). The client libraries are MIT; the Secure AI
service they talk to is a paid product and is not.
