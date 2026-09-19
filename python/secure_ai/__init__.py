"""Secure AI — data loss prevention for AI agents.

The API is plain HTTP and anybody can call it with ``requests``. This exists
because the shape that makes the product work is not "call an endpoint", it is
"put a check in front of every action", and the difference between those two is
whether somebody remembers to do it at the fourteenth call site.

So the centre of this package is :meth:`SecureAI.guard`, which wraps a function
an agent already calls and invokes it with the *rewritten* arguments::

    send = sai.guard("email.send", raw_send)
    send({"to": "ana@clientfirm.com"})   # raw_send receives a stand-in

Python before TypeScript would have been the better order — LangChain, CrewAI,
LlamaIndex and most agent code is Python — and this is the correction.

Why no dependencies
-------------------

This runs inside somebody's agent, beside their model client, their framework
and their vendor SDKs. Every dependency it adds is a version conflict it can
cause in a process already carrying too many, and a security tool that is
awkward to install is one that gets removed. So: ``urllib`` from the standard
library, nothing else. It is slower per call than ``httpx`` and that is not the
constraint — the constraint is that ``pip install secure-ai`` never fails.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal, TypeVar

__all__ = [
    "SecureAI",
    "ActionBlocked",
    "SecureAIError",
    "Finding",
    "Inspection",
    "KINDS",
]

__version__ = "0.1.0"

Decision = Literal["allow", "redact", "approve", "block"]
Direction = Literal["outbound", "inbound"]

#: Every kind the scanner reports, in the order a policy editor should list
#: them: the ones that end careers first. Mirrors KINDS in the Worker.
KINDS = (
    "secret", "card", "iban", "ssn", "govid",
    "email", "phone", "address", "postcode", "name", "host",
)

T = TypeVar("T")


@dataclass(frozen=True)
class Finding:
    """Something the scanner located: what it was and where it sat.

    Deliberately no ``value``. The trail never carries one and neither does
    this, so a caller logging a finding cannot accidentally log the thing the
    product exists to protect.
    """

    kind: str
    path: str
    decision: Decision


@dataclass(frozen=True)
class Inspection:
    decision: Decision
    #: The action, ready to send. ``None`` when blocked — a refusal carries
    #: nothing sendable, so a caller cannot reach past the decision.
    input: Any
    #: ``{stand_in: real}``. Keep it: it is the only way back, and it is not
    #: stored on our side.
    map: dict[str, str]
    findings: list[Finding]
    tool_denied: bool
    policy_source: str
    audit_id: str


class SecureAIError(RuntimeError):
    """The API answered, and said no.

    Distinct from :class:`ActionBlocked`: this is a problem with the call — no
    key, no subscription, over quota — not a decision about the action.
    """

    def __init__(self, message: str, status: int, code: str | None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class ActionBlocked(Exception):
    """The policy refused this action.

    Raised rather than returned so a caller cannot ignore it by not reading a
    field. A guarded function that returned a verdict would be protection you
    have to remember to check.
    """

    def __init__(self, tool: str, result: Inspection) -> None:
        if result.tool_denied:
            what = "the tool itself is not permitted"
        else:
            blocked = [f for f in result.findings if f.decision == "block"]
            what = ", ".join(f"{f.kind} at {f.path or 'the input'}" for f in blocked) or "policy"
        super().__init__(f"Secure AI refused {tool}: {what}.")
        self.tool = tool
        self.findings = result.findings
        self.tool_denied = result.tool_denied
        self.audit_id = result.audit_id


@dataclass
class SecureAI:
    """A client.

    :param api_key: from Settings → Developer.
    :param agent: names this agent in the trail so its actions group together.
        Worth setting — a trail where everything is unnamed is a trail nobody
        can ask a question of.
    :param on_unreachable: what to do when Secure AI itself cannot be reached.
        ``"closed"`` (the default) raises, so an action is not taken while the
        thing governing it is down. That is correct for a security control and
        it does mean an outage here stops agents. ``"open"`` lets the action
        through unchecked; it exists because some workloads genuinely prefer
        availability, and because somebody who wants it will otherwise write a
        ``try/except`` that also swallows real refusals.
    """

    api_key: str
    base_url: str = "https://api.secureai.one"
    agent: str | None = None
    timeout: float = 5.0
    on_unreachable: Literal["closed", "open"] = "closed"
    _opener: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.api_key:
            raise ValueError("SecureAI needs an api_key.")
        self.base_url = self.base_url.rstrip("/")

    # ── plumbing ────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        opener = self._opener or urllib.request.urlopen
        try:
            with opener(req, timeout=self.timeout) as res:  # type: ignore[operator]
                raw = res.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            message, code = f"Secure AI returned {exc.code}.", None
            try:
                err = (json.loads(raw) or {}).get("error") or {}
                message = err.get("message") or message
                code = err.get("code")
            except json.JSONDecodeError:
                # Something in front of the API answered, not the API.
                pass
            raise SecureAIError(message, exc.code, code) from None
        return json.loads(raw) if raw else None

    # ── the API ─────────────────────────────────────────────────────────────

    def inspect(
        self,
        tool: str,
        action_input: Any,
        *,
        direction: Direction = "outbound",
        agent: str | None = None,
    ) -> Inspection:
        """Judge an action without taking it."""
        body = self._request("POST", "/v1/inspect", {
            "tool": tool,
            "input": action_input,
            "direction": direction,
            "agent": agent or self.agent,
        })
        return Inspection(
            decision=body["decision"],
            input=body.get("input"),
            map=body.get("map") or {},
            findings=[Finding(f["kind"], f["path"], f["decision"]) for f in body.get("findings", [])],
            tool_denied=bool(body.get("toolDenied")),
            policy_source=body.get("policySource", "default"),
            audit_id=body.get("auditId", ""),
        )

    def get_policy(self) -> dict[str, Any]:
        """The rules in force."""
        return self._request("GET", "/v1/policy")

    def set_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Replace them. Refused whole if any rule is malformed, naming it."""
        return self._request("PUT", "/v1/policy", {"policy": policy})

    def allow_value(self, value: str) -> dict[str, Any]:
        """Stop flagging a value — your own domain, a shared mailbox.

        Applies to every agent on the account from the next action onward. A
        leading ``@`` exempts a whole domain.
        """
        return self._request("POST", "/v1/policy/allow", {"value": value})

    def audit(self, *, limit: int | None = None, cursor: str | None = None) -> dict[str, Any]:
        """What agents did, newest first. Kinds and locations, never values."""
        query = []
        if limit:
            query.append(f"limit={limit}")
        if cursor:
            query.append(f"cursor={urllib.parse.quote(cursor)}")
        suffix = f"?{'&'.join(query)}" if query else ""
        return self._request("GET", f"/v1/audit{suffix}")

    def summary(self, *, limit: int | None = None) -> dict[str, Any]:
        """The counts, over a recent window."""
        suffix = f"?limit={limit}" if limit else ""
        return self._request("GET", f"/v1/audit/summary{suffix}")

    def restore(self, text: str, mapping: dict[str, str]) -> str:
        """Put real values back into a reply, using an inspection's map."""
        return self._request("POST", "/v1/restore", {"text": text, "map": mapping})["text"]

    # ── the point of the library ────────────────────────────────────────────

    def guard(
        self,
        tool: str,
        fn: Callable[[Any], T],
        *,
        direction: Direction = "outbound",
        agent: str | None = None,
    ) -> Callable[[Any], T]:
        """Wrap a function so it cannot run unchecked.

        The returned callable inspects, then calls ``fn`` with the **rewritten**
        arguments — so an agent that never looks at a decision still cannot send
        a real card number — and raises :class:`ActionBlocked` when the policy
        refuses.

        Calling ``fn`` with the redacted input rather than the caller's is the
        whole mechanism. Returning a verdict for the caller to check would make
        protection opt-in at every site, which is what this exists to stop.
        """

        def guarded(action_input: Any) -> T:
            try:
                verdict = self.inspect(tool, action_input, direction=direction, agent=agent)
            except SecureAIError:
                # A refusal by the API is a real answer and must not be
                # mistaken for an outage, whatever on_unreachable says.
                raise
            except Exception:
                if self.on_unreachable == "open":
                    return fn(action_input)
                raise

            if verdict.decision == "block":
                raise ActionBlocked(tool, verdict)
            return fn(verdict.input if verdict.input is not None else action_input)

        guarded.__name__ = getattr(fn, "__name__", "guarded")
        guarded.__doc__ = getattr(fn, "__doc__", None)
        return guarded

    def guarded(self, tool: str, **kwargs: Any) -> Callable[[Callable[[Any], T]], Callable[[Any], T]]:
        """:meth:`guard` as a decorator.

        ::

            @sai.guarded("email.send")
            def send(payload): ...
        """

        def decorate(fn: Callable[[Any], T]) -> Callable[[Any], T]:
            return self.guard(tool, fn, **kwargs)

        return decorate

    def guard_tools(self, tools: Iterable[Any], *, name_attr: str = "name") -> list[Any]:
        """Wrap a list of framework tool objects in place.

        Agent frameworks hand around objects with a ``name`` and a callable —
        LangChain's ``StructuredTool``, an OpenAI function spec, a plain
        dataclass. This wraps whichever attribute holds the callable, so a
        whole toolbelt is governed in one line rather than tool by tool.

        Unknown shapes are returned untouched rather than raising: a helper
        that refuses to start because one tool in a list is unfamiliar is a
        helper nobody uses.
        """
        out = []
        for tool in tools:
            name = getattr(tool, name_attr, None) or getattr(tool, "__name__", None)
            for attr in ("func", "_run", "run", "fn", "callable"):
                target = getattr(tool, attr, None)
                if callable(target) and name:
                    try:
                        setattr(tool, attr, self.guard(str(name), target))
                    except (AttributeError, TypeError):
                        # Frozen or slotted objects cannot be patched. Left
                        # alone rather than failing the whole call.
                        pass
                    break
            out.append(tool)
        return out
