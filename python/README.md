# secure-ai

Data loss prevention for AI agents. Put a check in front of every action an
agent takes, before it takes it.

```bash
pip install secure-ai-guard
```

> **Status:** written, not yet executed — there was no Python interpreter on
> the machine this was built on. Run `pytest` before trusting it. The
> TypeScript SDK it mirrors does pass its suite.

## The one thing worth knowing

`guard` wraps a function your agent already calls, and calls it with the
**rewritten** arguments:

```python
from secure_ai import SecureAI

sai = SecureAI(api_key=os.environ["SECURE_AI_KEY"], agent="support-bot")

send_email = sai.guard("email.send", mailer.send)
send_email({"to": "ana@clientfirm.com", "body": "About invoice 4471…"})
```

The agent wrote a real address. `mailer.send` receives a stand-in. Nothing in
the agent's code had to check a decision — which is the point. Protection that
depends on remembering to check it ends at the fourteenth call site.

If the policy refuses, the wrapped function is never called and `ActionBlocked`
is raised.

As a decorator:

```python
@sai.guarded("email.send")
def send(payload): ...
```

## A whole toolbelt at once

```python
tools = sai.guard_tools(agent.tools)
```

Wraps whichever attribute holds the callable — `func`, `_run`, `run` — so
LangChain and similar frameworks are governed in one line. Shapes it does not
recognise are returned untouched rather than raising.

## Rules

Rules live on the account, not in the request. An agent cannot argue with them.

```python
sai.set_policy({
    "fallback": "redact",
    "rules": [
        {"kind": "secret", "decision": "block"},
        {"kind": "card", "decision": "block", "direction": "outbound"},
        {"kind": "email", "decision": "allow", "tools": ["crm.*"]},
    ],
    "denyTools": ["shell.*"],
})

sai.allow_value("@ourcompany.com")   # stop flagging your own domain
```

When an action contains several findings, the **most severe** decision wins.

## The trail

```python
sai.summary()                # counts over a recent window
sai.audit(limit=100)         # the records themselves
```

Records hold the **kind and location** of what was found — `card` at
`body.payment.number` — and never the value. `Finding` has no field for one.

## When Secure AI is unreachable

Default is `on_unreachable="closed"`: the action does not happen. Correct for a
security control, and it does mean an outage here stops agents.

```python
SecureAI(api_key=..., on_unreachable="open")   # availability over control
```

Failing open never waves a real refusal through — a 401, 402 or quota error is
an answer, not an outage, and still raises.

## No dependencies

Standard library only. This runs beside your model client and your framework,
and every dependency it adds is a version conflict it can cause.

Full reference: <https://secureai.one/developers>
