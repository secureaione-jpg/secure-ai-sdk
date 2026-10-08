import Foundation
import XCTest
@testable import SecureAI

/// Answers from a script, and remembers what it was asked.
final class FakeTransport: SecureAITransport, @unchecked Sendable {
    struct Asked { let method: String; let path: String; let headers: [String: String]; let body: JSONValue? }
    private let lock = NSLock()
    private var replies: [(Int, String)]
    private(set) var asked: [Asked] = []
    var unreachable = false

    init(_ replies: [(Int, String)]) { self.replies = replies }

    private func next(_ r: URLRequest) throws -> (Data, HTTPURLResponse) {
        lock.lock(); defer { lock.unlock() }
        let body = r.httpBody.flatMap { try? JSONDecoder().decode(JSONValue.self, from: $0) }
        asked.append(Asked(method: r.httpMethod ?? "", path: r.url!.path, headers: r.allHTTPHeaderFields ?? [:], body: body))
        if unreachable { throw URLError(.cannotConnectToHost) }
        let (status, text) = replies.isEmpty ? (500, "{}") : replies.removeFirst()
        return (Data(text.utf8), HTTPURLResponse(url: r.url!, statusCode: status, httpVersion: nil, headerFields: nil)!)
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) { try next(request) }

    func lines(_ request: URLRequest) async throws -> (AsyncThrowingStream<String, Error>, HTTPURLResponse) {
        let (data, http) = try next(request)
        let all = String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        return (AsyncThrowingStream { c in all.forEach { c.yield($0) }; c.finish() }, http)
    }
}

struct Mail: Codable, Sendable, Equatable { let to: String; let body: String }

final class SecureAITests: XCTestCase {
    func client(_ t: FakeTransport, open: Bool = false) -> SecureAI {
        SecureAI(apiKey: "sai_test", agent: "phone-app", whenUnreachable: open ? .open : .closed, transport: t)
    }

    func testRedactSendsKeyAndReadsMap() async throws {
        let t = FakeTransport([(200, #"{"object":"redaction","text":"Email Sylvie","map":{"Sylvie":"Sara"},"redacted":1,"names_decided":true}"#)])
        let r = try await client(t).redact("Email Sara")
        XCTAssertEqual(r.text, "Email Sylvie")
        XCTAssertEqual(r.map, ["Sylvie": "Sara"])
        XCTAssertEqual(t.asked[0].path, "/v1/redact")
        XCTAssertEqual(t.asked[0].headers["Authorization"], "Bearer sai_test")
        XCTAssertEqual(t.asked[0].body?["text"], "Email Sara")
        XCTAssertNil(t.asked[0].body?["strict"], "unset options are left out, not sent as null")
    }

    func testRestore() async throws {
        let t = FakeTransport([(200, #"{"object":"restoration","text":"I emailed Sara.","restored":1}"#)])
        let text = try await client(t).restore("I emailed Sylvie.", map: ["Sylvie": "Sara"])
        XCTAssertEqual(text, "I emailed Sara.")
        XCTAssertEqual(t.asked[0].body?["map"]?["Sylvie"], "Sara")
    }

    func testChatWithOurModels() async throws {
        let t = FakeTransport([(200, #"{"model":"secureai-auto","choices":[{"index":0,"message":{"role":"assistant","content":"Dear Sara"},"finish_reason":"stop"}]}"#)])
        let reply = try await client(t).chat([.user("Write to Sara")])
        XCTAssertEqual(reply.text, "Dear Sara")
        XCTAssertEqual(reply.finishReason, "stop")
        XCTAssertEqual(t.asked[0].path, "/v1/chat/completions")
        XCTAssertNil(t.asked[0].headers["X-Provider-Key"])
        XCTAssertNil(t.asked[0].body?["model"], "no model means we choose")
    }

    func testChatWithYourKeyGoesThroughTheProxy() async throws {
        let t = FakeTransport([(200, #"{"model":"claude-sonnet-5","choices":[{"message":{"content":"Hi"}}]}"#)])
        let text = try await client(t).chat("Hi", model: "claude-sonnet-5", using: .yourKey("sk-ant-x", provider: "anthropic"))
        XCTAssertEqual(text, "Hi")
        XCTAssertEqual(t.asked[0].path, "/v1/proxy/chat/completions")
        XCTAssertEqual(t.asked[0].headers["X-Provider-Key"], "sk-ant-x")
        XCTAssertEqual(t.asked[0].headers["X-Provider"], "anthropic")
    }

    func testYourKeyNeedsAModel() async {
        let t = FakeTransport([])
        do { _ = try await client(t).chat("Hi", using: .yourKey("sk")); XCTFail("should throw") }
        catch let e as SecureAIError { XCTAssertEqual(e.code, "model_required") }
        catch { XCTFail("\(error)") }
        XCTAssertTrue(t.asked.isEmpty, "nothing is sent")
    }

    func testStreamYieldsPieces() async throws {
        let sse = """
        data: {"choices":[{"delta":{"role":"assistant"}}]}
        data: {"choices":[{"delta":{"content":"Dear "}}]}
        : keep-alive
        data: {"choices":[{"delta":{"content":"Sara"}}]}
        data: [DONE]
        data: {"choices":[{"delta":{"content":"after done"}}]}
        """
        let t = FakeTransport([(200, sse)])
        var out = ""
        for try await piece in client(t).stream([.user("x")]) { out += piece }
        XCTAssertEqual(out, "Dear Sara")
        XCTAssertEqual(t.asked[0].body?["stream"], true)
    }

    func testStreamErrorStatusThrows() async {
        let t = FakeTransport([(402, #"{"error":{"message":"Out of balance","code":"insufficient_balance"}}"#)])
        do { for try await _ in client(t).stream([.user("x")]) {}; XCTFail("should throw") }
        catch let e as SecureAIError { XCTAssertEqual(e.status, 402); XCTAssertEqual(e.code, "insufficient_balance") }
        catch { XCTFail("\(error)") }
    }

    func testErrorsCarryStatusAndCode() async {
        let t = FakeTransport([(402, #"{"error":{"message":"Free allowance used","type":"insufficient_quota","code":"free_limit"}}"#)])
        do { _ = try await client(t).redact("x"); XCTFail("should throw") }
        catch let e as SecureAIError {
            XCTAssertEqual(e.status, 402); XCTAssertEqual(e.code, "free_limit"); XCTAssertEqual(e.message, "Free allowance used")
        } catch { XCTFail("\(error)") }
    }

    /* ── guard ── */

    func testGuardCallsWithTheRewrittenInput() async throws {
        let t = FakeTransport([(200, #"{"decision":"redact","input":{"to":"stand@in.com","body":"hi"},"map":{"stand@in.com":"ana@client.com"},"findings":[{"kind":"email","path":"to","decision":"redact"}],"toolDenied":false,"auditId":"a1"}"#)])
        let got = Box<Mail>()
        let send = client(t).guard("email.send") { (m: Mail) in got.value = m; return true }
        let ok = try await send(Mail(to: "ana@client.com", body: "hi"))
        XCTAssertTrue(ok)
        XCTAssertEqual(got.value?.to, "stand@in.com")
        XCTAssertEqual(t.asked[0].body?["tool"], "email.send")
        XCTAssertEqual(t.asked[0].body?["agent"], "phone-app")
        XCTAssertEqual(t.asked[0].body?["direction"], "outbound")
    }

    func testGuardBlockNeverCalls() async {
        let t = FakeTransport([(200, #"{"decision":"block","map":{},"findings":[{"kind":"card","path":"body","decision":"block"}],"toolDenied":false,"auditId":"a2"}"#)])
        let got = Box<Mail>()
        let send = client(t).guard("email.send") { (m: Mail) in got.value = m }
        do { try await send(Mail(to: "a", body: "4111")); XCTFail("should throw") }
        catch let e as ActionBlocked { XCTAssertEqual(e.auditId, "a2"); XCTAssertTrue(e.localizedDescription.contains("card at body")) }
        catch { XCTFail("\(error)") }
        XCTAssertNil(got.value)
    }

    func testRedactWithoutInputRefusesRatherThanSendingTheOriginal() async {
        let t = FakeTransport([(200, #"{"decision":"redact","map":{},"findings":[],"auditId":"a3"}"#)])
        let got = Box<Mail>()
        let send = client(t).guard("email.send") { (m: Mail) in got.value = m }
        do { try await send(Mail(to: "real@x.com", body: "b")); XCTFail("should throw") }
        catch let e as SecureAIError { XCTAssertEqual(e.code, "missing_rewritten_input") }
        catch { XCTFail("\(error)") }
        XCTAssertNil(got.value)
    }

    func testUnknownDecisionIsNotSent() async {
        let t = FakeTransport([(200, #"{"decision":"quarantine","input":{"to":"a","body":"b"},"map":{},"findings":[],"auditId":"a4"}"#)])
        let got = Box<Mail>()
        let send = client(t).guard("email.send") { (m: Mail) in got.value = m }
        do { try await send(Mail(to: "a", body: "b")); XCTFail("should throw") }
        catch let e as SecureAIError { XCTAssertEqual(e.code, "unknown_decision") }
        catch { XCTFail("\(error)") }
        XCTAssertNil(got.value)
    }

    func testAllowWithoutInputSendsTheOriginal() async throws {
        let t = FakeTransport([(200, #"{"decision":"allow","map":{},"findings":[],"auditId":"a5"}"#)])
        let got = Box<Mail>()
        let send = client(t).guard("email.send") { (m: Mail) in got.value = m }
        try await send(Mail(to: "a", body: "b"))
        XCTAssertEqual(got.value, Mail(to: "a", body: "b"))
    }

    func testApprovalWaitsThenRechecksWithTheId() async throws {
        let future = Date().timeIntervalSince1970 * 1000 + 60_000
        let t = FakeTransport([
            (200, #"{"decision":"approve","approvalId":"ap1","map":{},"findings":[],"auditId":"a6"}"#),
            (200, #"{"approval":{"id":"ap1","status":"approved","tool":"email.send","expiresAt":\#(future)}}"#),
            (200, #"{"decision":"allow","input":{"to":"a","body":"b"},"map":{},"findings":[],"auditId":"a7"}"#),
        ])
        let got = Box<Mail>()
        let send = client(t).guard("email.send") { (m: Mail) in got.value = m }
        try await send(Mail(to: "a", body: "b"))
        XCTAssertEqual(got.value, Mail(to: "a", body: "b"))
        XCTAssertEqual(t.asked.map(\.path), ["/v1/inspect", "/v1/approvals/ap1", "/v1/inspect"])
        XCTAssertEqual(t.asked[2].body?["approvalId"], "ap1")
    }

    func testDeniedApprovalThrowsWithTheNote() async {
        let t = FakeTransport([
            (200, #"{"decision":"approve","approvalId":"ap2","map":{},"findings":[],"auditId":"a8"}"#),
            (200, #"{"approval":{"id":"ap2","status":"denied","tool":"pay","expiresAt":1,"note":"wrong customer"}}"#),
        ])
        let send = client(t).guard("pay") { (m: Mail) in XCTFail("must not run") }
        do { try await send(Mail(to: "a", body: "b")); XCTFail("should throw") }
        catch let e as ApprovalRefused { XCTAssertEqual(e.status, .denied); XCTAssertEqual(e.note, "wrong customer") }
        catch { XCTFail("\(error)") }
    }

    func testMissingExpiryCountsAsExpired() async throws {
        let t = FakeTransport([(200, #"{"approval":{"id":"ap3","status":"pending","tool":"pay"}}"#)])
        let a = try await client(t).waitForApproval("ap3")
        XCTAssertEqual(a.status, .expired)
        XCTAssertEqual(t.asked.count, 1, "does not poll forever")
    }

    func testUnreachableIsClosedByDefault() async {
        let t = FakeTransport([]); t.unreachable = true
        let got = Box<Mail>()
        let send = client(t).guard("email.send") { (m: Mail) in got.value = m }
        do { try await send(Mail(to: "a", body: "b")); XCTFail("should throw") } catch {}
        XCTAssertNil(got.value)
    }

    func testUnreachableOpenGoesAhead() async throws {
        let t = FakeTransport([]); t.unreachable = true
        let got = Box<Mail>()
        let send = client(t, open: true).guard("email.send") { (m: Mail) in got.value = m }
        try await send(Mail(to: "a", body: "b"))
        XCTAssertEqual(got.value, Mail(to: "a", body: "b"))
    }

    func testOpenStillHonoursARefusal() async {
        let t = FakeTransport([(401, #"{"error":{"message":"Bad key","code":"invalid_api_key"}}"#)])
        let got = Box<Mail>()
        let send = client(t, open: true).guard("email.send") { (m: Mail) in got.value = m }
        do { try await send(Mail(to: "a", body: "b")); XCTFail("should throw") }
        catch let e as SecureAIError { XCTAssertEqual(e.status, 401) }
        catch { XCTFail("\(error)") }
        XCTAssertNil(got.value)
    }

    func testDefaultsToTheDocumentedAddress() throws {
        let req = try SecureAI(apiKey: "sai_x").makeRequest("GET", "/v1/usage")
        XCTAssertEqual(req.url?.absoluteString, "https://secureai.one/v1/usage")
    }
}

final class Box<T>: @unchecked Sendable { var value: T? }
