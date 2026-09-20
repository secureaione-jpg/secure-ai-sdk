"""The Python SDK.

These run. They were written believing the machine had no interpreter — the
Microsoft Store alias on PATH answers "Python was not found", and the real
3.12 install sits in AppData a directory away — so for a while this file said
it had never been executed. It has: locally, and on both legs of CI.

The behaviour worth most of these: ``guard`` calls the wrapped function with
the *rewritten* input, not the caller's. That is what makes protection
automatic rather than opt-in, and a refactor could quietly undo it — every test
here would still pass if guard merely returned a verdict, unless one of them
checks what the underlying function actually received.
"""

from __future__ import annotations

import io
import json
import time
import urllib.error

import pytest

from secure_ai import (
    ActionBlocked,
    ApprovalRefused,
    Finding,
    SecureAI,
    SecureAIError,
)


class FakeResponse:
    def __init__(self, body: object, status: int = 200) -> None:
        self._raw = json.dumps(body).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None


def client(handler, **kwargs):
    """A client whose opener records calls and returns what `handler` says."""
    calls: list[dict] = []

    def opener(req, timeout=None):  # noqa: ARG001 - signature matches urlopen
        body = json.loads(req.data.decode("utf-8")) if req.data else None
        calls.append({
            "url": req.full_url,
            "method": req.get_method(),
            "body": body,
            "headers": {k.lower(): v for k, v in req.headers.items()},
        })
        result = handler(req)
        if isinstance(result, urllib.error.HTTPError):
            raise result
        return result

    sai = SecureAI(api_key="sai_test", base_url="https://api.test", _opener=opener, **kwargs)
    return calls, sai


def http_error(status: int, body: object) -> urllib.error.HTTPError:
    payload = json.dumps(body).encode("utf-8")
    return urllib.error.HTTPError(
        "https://api.test", status, "err", {}, io.BytesIO(payload)
    )


def allowed(value: object) -> FakeResponse:
    return FakeResponse({
        "decision": "allow", "input": value, "map": {}, "findings": [],
        "toolDenied": False, "policySource": "default", "auditId": "a1",
    })


def redacted(value: object, mapping: dict) -> FakeResponse:
    return FakeResponse({
        "decision": "redact", "input": value, "map": mapping, "findings": [],
        "toolDenied": False, "policySource": "account", "auditId": "a2",
    })


def blocked(findings: list | None = None, tool_denied: bool = False) -> FakeResponse:
    return FakeResponse({
        "decision": "block", "map": {},
        "findings": findings if findings is not None else
            [{"kind": "secret", "path": "headers.authorization", "decision": "block"}],
        "toolDenied": tool_denied, "policySource": "account", "auditId": "a3",
    })


class TestConstruction:
    def test_insists_on_a_key(self) -> None:
        with pytest.raises(ValueError, match="api_key"):
            SecureAI(api_key="")

    def test_trims_a_trailing_slash_rather_than_doubling_it(self) -> None:
        calls, sai = client(lambda _r: allowed({}))
        sai.base_url = "https://api.test/"
        sai.__post_init__()
        sai.inspect("t", {})
        assert calls[0]["url"] == "https://api.test/v1/inspect"


class TestInspect:
    def test_sends_the_action_with_outbound_as_the_default(self) -> None:
        calls, sai = client(lambda _r: allowed({"a": 1}))
        sai.inspect("http.post", {"a": 1})
        assert calls[0]["body"]["tool"] == "http.post"
        assert calls[0]["body"]["direction"] == "outbound"

    def test_names_the_agent_from_the_client(self) -> None:
        calls, sai = client(lambda _r: allowed({}), agent="nightly-sync")
        sai.inspect("t", {})
        assert calls[0]["body"]["agent"] == "nightly-sync"

    def test_sends_the_key_as_a_bearer(self) -> None:
        calls, sai = client(lambda _r: allowed({}))
        sai.inspect("t", {})
        assert calls[0]["headers"]["authorization"] == "Bearer sai_test"

    def test_turns_a_refusal_into_an_error_carrying_the_code(self) -> None:
        _calls, sai = client(lambda _r: http_error(402, {
            "error": {"message": "No API access.", "code": "api_access_required"}
        }))
        with pytest.raises(SecureAIError) as caught:
            sai.inspect("t", {})
        assert caught.value.status == 402
        assert caught.value.code == "api_access_required"

    def test_survives_a_non_json_body_from_something_in_front_of_the_api(self) -> None:
        def opener(req, timeout=None):  # noqa: ARG001
            raise urllib.error.HTTPError(req.full_url, 502, "bad", {}, io.BytesIO(b"<html>"))

        sai = SecureAI(api_key="k", base_url="https://api.test", _opener=opener)
        with pytest.raises(SecureAIError) as caught:
            sai.inspect("t", {})
        assert caught.value.status == 502


class TestGuard:
    def test_calls_the_function_with_the_rewritten_input(self) -> None:
        """The whole mechanism.

        If this passes while ``send`` receives the caller's original dict, the
        library protects nothing.
        """
        real = {"to": "ana@example.org"}
        safe = {"to": "person1@example.com"}
        _calls, sai = client(lambda _r: redacted(safe, {"person1@example.com": "ana@example.org"}))

        seen: list[dict] = []

        def send(payload: dict) -> str:
            seen.append(payload)
            return f"sent to {payload['to']}"

        out = sai.guard("email.send", send)(real)
        assert seen == [safe]
        assert out == "sent to person1@example.com"

    def test_raises_and_never_calls_the_function_when_refused(self) -> None:
        _calls, sai = client(lambda _r: blocked())
        called: list[object] = []

        with pytest.raises(ActionBlocked):
            sai.guard("http.post", lambda payload: called.append(payload))({})
        assert called == []

    def test_says_what_was_refused(self) -> None:
        _calls, sai = client(lambda _r: blocked())
        with pytest.raises(ActionBlocked, match=r"secret at headers\.authorization"):
            sai.guard("http.post", lambda _p: "x")({})

    def test_explains_a_denied_tool_differently(self) -> None:
        _calls, sai = client(lambda _r: blocked(findings=[], tool_denied=True))
        with pytest.raises(ActionBlocked, match="tool itself is not permitted"):
            sai.guard("shell.exec", lambda _p: "x")({})

    def test_passes_an_allowed_action_through(self) -> None:
        payload = {"q": "orders shipped yesterday"}
        _calls, sai = client(lambda _r: allowed(payload))
        assert sai.guard("db.query", lambda p: p["q"])(payload) == "orders shipped yesterday"

    def test_works_as_a_decorator(self) -> None:
        _calls, sai = client(lambda _r: allowed({"a": 1}))

        @sai.guarded("db.query")
        def run(payload: dict) -> dict:
            return payload

        assert run({"a": 1}) == {"a": 1}
        assert run.__name__ == "run"


class TestUnreachable:
    @staticmethod
    def _dead(req, timeout=None):  # noqa: ARG004
        raise OSError("network down")

    def test_fails_closed_by_default(self) -> None:
        sai = SecureAI(api_key="k", _opener=self._dead)
        called: list[object] = []
        with pytest.raises(OSError):
            sai.guard("t", lambda p: called.append(p))({})
        assert called == []

    def test_fails_open_when_asked(self) -> None:
        sai = SecureAI(api_key="k", _opener=self._dead, on_unreachable="open")
        assert sai.guard("t", lambda _p: "done")({}) == "done"

    def test_an_answered_refusal_is_not_an_outage(self) -> None:
        """Failing open must never wave a 401 through as a blinked network."""
        _calls, sai = client(
            lambda _r: http_error(401, {"error": {"message": "bad key", "code": "invalid_api_key"}}),
            on_unreachable="open",
        )
        called: list[object] = []
        with pytest.raises(SecureAIError):
            sai.guard("t", lambda p: called.append(p))({})
        assert called == []


class TestPolicyAndTrail:
    def test_reads_and_replaces_the_policy(self) -> None:
        calls, sai = client(lambda _r: FakeResponse({"policy": {"version": 1, "fallback": "block", "rules": []}}))
        sai.set_policy({"fallback": "block", "rules": []})
        assert calls[0]["method"] == "PUT"
        assert calls[0]["body"] == {"policy": {"fallback": "block", "rules": []}}

    def test_exempts_a_value(self) -> None:
        calls, sai = client(lambda _r: FakeResponse({"policy": {}, "added": "@ours.com"}))
        sai.allow_value("@ours.com")
        assert calls[0]["url"] == "https://api.test/v1/policy/allow"
        assert calls[0]["body"] == {"value": "@ours.com"}

    def test_passes_paging_on_the_query_string(self) -> None:
        calls, sai = client(lambda _r: FakeResponse({"events": [], "cursor": None}))
        sai.audit(limit=10, cursor="abc")
        assert calls[0]["url"] == "https://api.test/v1/audit?limit=10&cursor=abc"

    def test_asks_for_the_trail_plainly_when_unpaged(self) -> None:
        calls, sai = client(lambda _r: FakeResponse({"events": [], "cursor": None}))
        sai.audit()
        assert calls[0]["url"] == "https://api.test/v1/audit"

    def test_restores_a_reply(self) -> None:
        _calls, sai = client(lambda _r: FakeResponse({"text": "call ana@example.org"}))
        assert sai.restore("call person1@example.com", {"person1@example.com": "ana@example.org"}) \
            == "call ana@example.org"


class TestFindings:
    def test_a_finding_has_no_place_to_put_a_value(self) -> None:
        """The trail carries kinds and locations. So does this."""
        assert set(Finding.__dataclass_fields__) == {"kind", "path", "decision"}


class TestGuardTools:
    def test_wraps_a_framework_tool_in_place(self) -> None:
        _calls, sai = client(lambda _r: allowed({"a": 1}))

        class Tool:
            name = "db.query"

            def __init__(self) -> None:
                self.func = lambda payload: payload

        tool = Tool()
        sai.guard_tools([tool])
        assert tool.func({"a": 1}) == {"a": 1}

    def test_leaves_an_unfamiliar_shape_alone_rather_than_raising(self) -> None:
        _calls, sai = client(lambda _r: allowed({}))
        odd = object()
        assert sai.guard_tools([odd]) == [odd]


class TestHeldForAPerson:
    """The branch that did not exist.

    ``guard`` handled ``block`` and nothing else, so an ``approve`` decision
    fell through to the send. On Python a policy saying an action must wait
    for a human was not weakened but bypassed, and the agent was told the
    check had passed.
    """

    @staticmethod
    def _held(approval_id="ap1"):
        return {
            "decision": "approve",
            "approvalId": approval_id,
            "expiresAt": int(time.time() * 1000) + 600_000,
            "map": {},
            "findings": [{"kind": "card", "path": "body.note", "decision": "approve"}],
            "toolDenied": False,
            "policySource": "account",
            "auditId": "a1",
        }

    @staticmethod
    def _approval(status, **extra):
        base = {
            "id": "ap1",
            "createdAt": int(time.time() * 1000) - 1000,
            "expiresAt": int(time.time() * 1000) + 600_000,
            "status": status,
            "agent": "billing",
            "tool": "mail.send",
            "keyId": "k1",
            "findings": [],
        }
        base.update(extra)
        return {"approval": base}

    def test_waits_then_sends_once_a_person_says_yes(self):
        seen = []

        def handler(req):
            if req.full_url.endswith("/v1/inspect"):
                body = json.loads(req.data.decode("utf-8"))
                if body.get("approvalId"):
                    return FakeResponse({
                        "decision": "allow",
                        "input": {"note": "go ahead"},
                        "map": {}, "findings": [], "toolDenied": False,
                        "policySource": "account", "auditId": "a2",
                    })
                return FakeResponse(self._held())
            return FakeResponse(self._approval("approved"))

        _, sai = client(handler)

        def send(payload):
            seen.append(payload)
            return "sent"

        assert sai.guard("mail.send", send)({"note": "original"}) == "sent"
        # It went, and it went with what came back from the second check.
        assert seen == [{"note": "go ahead"}]

    def test_does_not_send_when_the_person_says_no(self):
        def handler(req):
            if req.full_url.endswith("/v1/inspect"):
                return FakeResponse(self._held())
            return FakeResponse(self._approval("denied", note="not this customer"))

        _, sai = client(handler)
        sent = []

        with pytest.raises(ApprovalRefused) as caught:
            sai.guard("mail.send", lambda p: sent.append(p))({"note": "x"})
        assert caught.value.status == "denied"
        assert "not this customer" in str(caught.value)
        assert sent == []

    def test_an_expiry_is_a_refusal_not_a_release(self):
        def handler(req):
            if req.full_url.endswith("/v1/inspect"):
                return FakeResponse(self._held())
            return FakeResponse(self._approval("expired"))

        _, sai = client(handler)
        sent = []
        with pytest.raises(ApprovalRefused) as caught:
            sai.guard("mail.send", lambda p: sent.append(p))({"note": "x"})
        assert caught.value.status == "expired"
        assert sent == []

    def test_can_refuse_to_wait_and_hand_the_id_back(self):
        _, sai = client(lambda req: FakeResponse(self._held()))
        sent = []
        with pytest.raises(ApprovalRefused) as caught:
            sai.guard("mail.send", lambda p: sent.append(p), wait_for_approval=False)({"a": 1})
        assert caught.value.status == "pending"
        assert caught.value.approval_id == "ap1"
        assert sent == []

    def test_a_held_action_with_no_id_is_refused_rather_than_sent(self):
        held = self._held()
        del held["approvalId"]
        _, sai = client(lambda req: FakeResponse(held))
        sent = []
        with pytest.raises(ActionBlocked):
            sai.guard("mail.send", lambda p: sent.append(p))({"a": 1})
        assert sent == []

    def test_reads_the_queue(self):
        def handler(req):
            assert "status=pending" in req.full_url
            return FakeResponse({"approvals": [self._approval("pending")["approval"]]})

        _, sai = client(handler)
        queue = sai.approvals(status="pending")
        assert len(queue) == 1
        assert queue[0].tool == "mail.send"
        assert queue[0].status == "pending"

    def test_escapes_the_id_in_the_path(self):
        calls, sai = client(lambda req: FakeResponse(self._approval("approved")))
        sai.approval("a/b?c")
        assert "a%2Fb%3Fc" in calls[0]["url"]


class TestARedactWithNothingToSend:
    """The fallback that braced open.

    The API omits ``input`` only on a block, so on a redact it is always
    there — until some day it is not. ``guard`` fell back to the caller's own
    input, which on a redact is the one thing that must not go: it still
    holds the values the decision had just said to replace.
    """

    BROKEN = {
        "decision": "redact",
        "map": {},
        "findings": [],
        "toolDenied": False,
        "policySource": "account",
        "auditId": "a9",
    }

    def test_raises_rather_than_sending_the_original(self):
        _, sai = client(lambda req: FakeResponse(self.BROKEN))
        sent = []
        with pytest.raises(SecureAIError) as caught:
            sai.guard("mail.send", lambda p: sent.append(p))({"to": "ana@clientfirm.com"})
        assert "nothing to send" in str(caught.value)
        assert sent == []

    def test_an_allow_still_passes_the_original_through(self):
        allowed = dict(self.BROKEN, decision="allow")
        _, sai = client(lambda req: FakeResponse(allowed))
        original = {"note": "nothing sensitive"}
        assert sai.guard("mail.send", lambda p: p)(original) == original


class TestADecisionThisVersionDoesNotKnow:
    """Only allow and redact mean "this may go".

    The check used to be the other way round -- refuse on block, refuse on
    approve, send otherwise -- and that is how "approve" itself got sent when
    it was introduced: the client compared against "block", found no match,
    and called through. A policy gains a decision, an agent keeps an older
    client, and the failure has to be a refusal rather than a send.
    """

    UNKNOWN = {
        "decision": "quarantine",
        "map": {},
        "findings": [],
        "toolDenied": False,
        "policySource": "account",
        "auditId": "a11",
    }

    def test_refuses_rather_than_sending(self):
        _, sai = client(lambda req: FakeResponse(self.UNKNOWN))
        sent = []
        with pytest.raises(SecureAIError) as caught:
            sai.guard("mail.send", lambda p: sent.append(p))({"note": "hello"})
        assert "does not know how to send safely" in str(caught.value)
        assert sent == []

    def test_names_the_decision_and_the_code(self):
        _, sai = client(lambda req: FakeResponse(self.UNKNOWN))
        with pytest.raises(SecureAIError) as caught:
            sai.guard("mail.send", lambda p: p)({"note": "hello"})
        assert "quarantine" in str(caught.value)
        assert caught.value.code == "unknown_decision"

    def test_refuses_on_the_re_check_after_an_approval(self):
        """The second inspect is the last thing between a yes and the action."""
        state = {"inspects": 0}

        def handler(req):
            if req.full_url.endswith("/v1/inspect"):
                state["inspects"] += 1
                if state["inspects"] == 1:
                    return FakeResponse({
                        "decision": "approve",
                        "approvalId": "ap_1",
                        "findings": [],
                        "toolDenied": False,
                        "policySource": "account",
                        "auditId": "a12",
                    })
                return FakeResponse(self.UNKNOWN)
            return FakeResponse({
                "approval": {"id": "ap_1", "status": "approved", "tool": "mail.send"}
            })

        _, sai = client(handler)
        sent = []
        with pytest.raises(SecureAIError) as caught:
            sai.guard("mail.send", lambda p: sent.append(p), poll_seconds=0.01)(
                {"note": "hello"}
            )
        assert "does not know how to send safely" in str(caught.value)
        assert sent == []


class TestAnApprovalWithNoExpiry:
    """The wait loop stops at the approval's own expiry, so the expiry has
    to be a number.

    _approval already coerces a missing one to 0, which reads as already
    expired and refuses. Nothing pinned that, and the TypeScript client --
    which did not coerce -- polled a metered API every two seconds forever
    when handed the same body. Untested correctness on one side and a live
    bug on the other is the same omission twice.
    """

    def test_refuses_instead_of_polling_forever(self):
        polls = {"n": 0}

        def handler(req):
            if "/v1/approvals/" in req.full_url:
                polls["n"] += 1
                return FakeResponse({
                    "approval": {"id": "ap_1", "status": "pending", "tool": "mail.send"}
                })
            return FakeResponse({
                "decision": "approve",
                "approvalId": "ap_1",
                "findings": [],
                "toolDenied": False,
                "policySource": "account",
                "auditId": "a13",
            })

        _, sai = client(handler)
        sent = []
        with pytest.raises(ApprovalRefused) as caught:
            sai.guard("mail.send", lambda p: sent.append(p), poll_seconds=0.01)(
                {"note": "hello"}
            )
        assert caught.value.status == "expired"
        assert sent == []
        # One look, then the missing expiry decides it. Not a loop.
        assert polls["n"] == 1
