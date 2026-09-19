"""The Python SDK.

NOT YET EXECUTED. There is no Python interpreter on the machine this was
written on, so every test below is unrun. They are written to the same shape as
the TypeScript suite — which does pass — and the behaviours they pin are the
ones that suite already proves at the API boundary, so the risk is in this
file's own syntax rather than in what it asserts. Run ``pytest`` once before
trusting any of it, and treat a first-run failure as a bug in the SDK, not as
a surprise.

The behaviour worth most of these: ``guard`` calls the wrapped function with
the *rewritten* input, not the caller's. That is what makes protection
automatic rather than opt-in, and a refactor could quietly undo it — every test
here would still pass if guard merely returned a verdict, unless one of them
checks what the underlying function actually received.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from secure_ai import ActionBlocked, Finding, SecureAI, SecureAIError


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
