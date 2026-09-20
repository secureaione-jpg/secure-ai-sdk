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
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Literal, TypeVar
from urllib.parse import quote, urlencode

__all__ = [
    "SecureAI",
    "ActionBlocked",
    "ApprovalRefused",
    "SecureAIError",
    "Approval",
    "Finding",
    "Inspection",
    "KINDS",
]

__version__ = "0.2.0"

Decision = Literal["allow", "redact", "approve", "block"]
Direction = Literal["outbound", "inbound"]
ApprovalStatus = Literal["pending", "approved", "denied", "expired"]

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
    #: Set when the decision is "approve": the id to come back with once a
    #: person has decided.
    approval_id: str | None = None
    #: When waiting stops being worth it. Milliseconds since epoch.
    expires_at: int | None = None


def _sendable(tool: str, verdict: "Inspection", original: Any) -> Any:
    """What to hand the wrapped function.

    The API omits ``input`` only on a block, so on any other decision it is
    there. The question is what to do if it is not, and the answer is not
    "send what the caller had".

    On a redact the caller's input is the one thing that must not go: it still
    holds the values the decision just said to replace. Falling back to it
    turns a missing field into the library doing the exact opposite of its
    purpose, silently, with the trail recording a redaction that did not
    happen.

    On an allow nothing was rewritten, so the caller's own input is the right
    thing to pass and the fallback belongs there.

    Which decisions may send, rather than which may not
    ---------------------------------------------------

    Two decisions mean "this may go": allow and redact. Every other value,
    present or future, means it may not. Asked the other way round -- refuse
    on block, refuse on approve, send otherwise -- a decision added to the
    policy later is sent by a client that has never heard of it, and the
    agent is told the check passed.

    That is not hypothetical. It is the bug the branch in :meth:`guard`
    still carries a comment about: "approve" was added, the check compared
    against "block" and nothing else, and an action a policy said must wait
    for a person went immediately. The same shape cost ten fixes across the
    Worker, the dashboard and both clients.

    Reachable today? No. The Worker answers 409 rather than a second
    "approve" when an approval cannot be redeemed, so the re-check after a
    yes comes back allow, redact, or an error. This is the client declining
    to depend on that, across a version boundary it does not control.
    """
    if verdict.decision not in ("allow", "redact"):
        raise SecureAIError(
            f'Secure AI answered "{verdict.decision}" for {tool}, which this '
            "version does not know how to send safely. Nothing was sent. "
            "Upgrade secure-ai-guard.",
            502,
            "unknown_decision",
        )
    if verdict.input is not None:
        return verdict.input
    if verdict.decision == "redact":
        raise SecureAIError(
            f"Secure AI decided to redact {tool} but returned nothing to send. "
            "The original was not sent: it still holds the values that decision was about.",
            502,
            "missing_rewritten_input",
        )
    return original


def _approval(raw: dict[str, Any]) -> "Approval":
    return Approval(
        id=raw.get("id", ""),
        created_at=int(raw.get("createdAt", 0)),
        expires_at=int(raw.get("expiresAt", 0)),
        status=raw.get("status", "pending"),
        agent=raw.get("agent"),
        tool=raw.get("tool", ""),
        key_id=raw.get("keyId", ""),
        findings=[Finding(f["kind"], f["path"], f["decision"]) for f in raw.get("findings", [])],
        decided_by=raw.get("decidedBy"),
        decided_at=raw.get("decidedAt"),
        note=raw.get("note"),
    )


@dataclass(frozen=True)
class Approval:
    """An action a rule stopped and handed to a person.

    Holds the shape of what the agent wanted to do — the tool and the kinds it
    carried — and never the payload, for the same reason the trail does not.
    """

    id: str
    created_at: int
    expires_at: int
    status: ApprovalStatus
    agent: str | None
    tool: str
    key_id: str
    findings: list[Finding]
    decided_by: str | None = None
    decided_at: int | None = None
    note: str | None = None


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


class ApprovalRefused(Exception):
    """A person was asked, and the action did not go.

    Three ways to arrive here and they are not the same: denied means somebody
    looked and said no; expired means nobody looked in time, which is also a
    no because an approval that runs out is a refusal rather than a release;
    pending means the caller asked not to wait.
    """

    def __init__(
        self,
        tool: str,
        approval_id: str,
        status: ApprovalStatus,
        note: str | None = None,
    ) -> None:
        if status == "pending":
            what = "and it is still waiting for a person"
        elif status == "expired":
            what = "and nobody answered before it expired"
        else:
            what = "and it was refused" + (": " + note if note else "")
        super().__init__(f"Secure AI held {tool} for approval {what}.")
        self.tool = tool
        self.approval_id = approval_id
        self.status = status
        self.note = note


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
    #: Where the client talks to, when nobody says otherwise.
    #:
    #: This was an api. subdomain in 0.2.0, and that host does not
    #: exist -- it was never created. Nothing caught it:
    #: the tests pass a base_url, and the package built and published
    #: cleanly. The first person to pip install this and follow the README
    #: would have got a DNS failure on their first call.
    #:
    #: secureai.one/v1 is the address the docs have always given and it is
    #: proxied to the Worker, so this is the same endpoint the curl
    #: examples hit.
    base_url: str = "https://secureai.one"
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
            with opener(req, timeout=self.timeout) as res:
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
        approval_id: str | None = None,
    ) -> Inspection:
        """Judge an action without taking it.

        Pass ``approval_id`` to come back with a yes a person has given.
        The server re-checks the shape of what is being sent against what was
        approved, so one yes cannot be spent on a different action.
        """
        payload: dict[str, Any] = {
            "tool": tool,
            "input": action_input,
            "direction": direction,
            "agent": agent or self.agent,
        }
        if approval_id:
            payload["approvalId"] = approval_id
        body = self._request("POST", "/v1/inspect", payload)
        return Inspection(
            decision=body["decision"],
            input=body.get("input"),
            map=body.get("map") or {},
            findings=[Finding(f["kind"], f["path"], f["decision"]) for f in body.get("findings", [])],
            tool_denied=bool(body.get("toolDenied")),
            policy_source=body.get("policySource", "default"),
            audit_id=body.get("auditId", ""),
            approval_id=body.get("approvalId"),
            expires_at=body.get("expiresAt"),
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

    def approval(self, approval_id: str) -> Approval:
        """Read one back."""
        body = self._request("GET", f"/v1/approvals/{quote(approval_id, safe='')}")
        return _approval(body["approval"])

    def approvals(
        self,
        *,
        status: ApprovalStatus | None = None,
        limit: int | None = None,
    ) -> list[Approval]:
        """The queue, newest first."""
        query: dict[str, Any] = {}
        if status:
            query["status"] = status
        if limit:
            query["limit"] = limit
        path = "/v1/approvals" + ("?" + urlencode(query) if query else "")
        return [_approval(a) for a in self._request("GET", path).get("approvals", [])]

    def wait_for_approval(self, approval_id: str, *, poll_seconds: float = 2.0) -> Approval:
        """Block until somebody decides, or until the window closes.

        Stops at the approval's own expiry rather than running forever: the
        server denies it at that point regardless, so a caller polling past it
        is waiting for an answer that has already been given.
        """
        while True:
            current = self.approval(approval_id)
            if current.status != "pending":
                return current
            if time.time() * 1000 >= current.expires_at:
                return replace(current, status="expired")
            time.sleep(poll_seconds)

    def guard(
        self,
        tool: str,
        fn: Callable[[Any], T],
        *,
        direction: Direction = "outbound",
        agent: str | None = None,
        wait_for_approval: bool = True,
        poll_seconds: float = 2.0,
    ) -> Callable[[Any], T]:
        """Wrap a function so it cannot run unchecked.

        The returned callable inspects, then calls ``fn`` with the **rewritten**
        arguments — so an agent that never looks at a decision still cannot send
        a real card number — and raises :class:`ActionBlocked` when the policy
        refuses.

        Calling ``fn`` with the redacted input rather than the caller's is the
        whole mechanism. Returning a verdict for the caller to check would make
        protection opt-in at every site, which is what this exists to stop.

        An action held for a person waits by default. Pass
        ``wait_for_approval=False`` to get :class:`ApprovalRefused` straight
        away and do the waiting yourself.
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

            # Held for a person.
            #
            # This branch did not exist. "approve" did not match "block", so
            # the action was sent immediately: on Python a policy saying an
            # action must wait for a human was not weakened but bypassed, and
            # the agent was told the check had passed.
            if verdict.decision == "approve":
                approval_id = verdict.approval_id or ""
                if not approval_id:
                    raise ActionBlocked(tool, verdict)
                if not wait_for_approval:
                    raise ApprovalRefused(tool, approval_id, "pending")
                decided = self.wait_for_approval(approval_id, poll_seconds=poll_seconds)
                if decided.status != "approved":
                    raise ApprovalRefused(tool, approval_id, decided.status, decided.note)
                # Back with the id. The server re-checks the shape of what is
                # being sent, so a yes cannot be spent on a different action.
                after = self.inspect(
                    tool,
                    action_input,
                    direction=direction,
                    agent=agent,
                    approval_id=approval_id,
                )
                if after.decision == "block":
                    raise ActionBlocked(tool, after)
                return fn(_sendable(tool, after, action_input))

            return fn(_sendable(tool, verdict, action_input))

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
