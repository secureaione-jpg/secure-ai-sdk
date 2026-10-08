import Foundation

/// The Secure AI client for Apple platforms.
///
/// Two jobs, and most apps want the first:
///
/// - **Private chat.** `chat` sends a conversation to a model with every
///   name, email, phone number and card swapped for a stand-in first, and the
///   real ones put back in the answer. With our models, or with your own key.
/// - **Guarded actions.** `guard` wraps something your app's agent does —
///   send an email, charge a card — so it cannot run until the account's
///   rules have looked at it, and runs with the stand-ins when they say so.
///
/// It is the same API as the TypeScript and Python clients; the names follow
/// Swift rather than them.
///
/// ── Your key in an app ──
///
/// Anything compiled into an app can be read out of it. Keep the key on your
/// server and point `baseURL` at a route there that adds it, or give the key
/// the app carries a monthly spending limit (Settings → Developer) so a key
/// lifted from the app cannot spend more than that.
public final class SecureAI: Sendable {
    public enum WhenUnreachable: Sendable {
        /// The action does not happen, and the error is thrown. The default:
        /// a privacy control that steps aside when it is down is not one.
        case closed
        /// Guarded actions go ahead unchecked. A refusal is still a refusal:
        /// only failing to reach Secure AI at all lets an action through.
        case open
    }

    let apiKey: String
    let baseURL: URL
    let agent: String?
    let timeout: TimeInterval
    let transport: SecureAITransport
    let whenUnreachable: WhenUnreachable

    /// - Parameters:
    ///   - apiKey: `sai_…`, from Settings → Developer.
    ///   - baseURL: The origin, without `/v1`. Change it for your own server.
    ///   - agent: Names this app's actions in the audit trail.
    ///   - timeout: Seconds before a check is abandoned. Chat waits longer.
    public init(
        apiKey: String,
        baseURL: URL = URL(string: "https://secureai.one")!,
        agent: String? = nil,
        timeout: TimeInterval = 10,
        whenUnreachable: WhenUnreachable = .closed,
        transport: SecureAITransport = URLSessionTransport()
    ) {
        precondition(!apiKey.isEmpty, "SecureAI needs an apiKey.")
        self.apiKey = apiKey
        self.baseURL = baseURL
        self.agent = agent
        self.timeout = timeout
        self.whenUnreachable = whenUnreachable
        self.transport = transport
    }

    static let chatTimeout: TimeInterval = 120

    /* ── Plumbing ─────────────────────────────────────────────────────── */

    func makeRequest(_ method: String, _ path: String, body: Encodable? = nil,
                     headers: [String: String] = [:], timeout: TimeInterval? = nil) throws -> URLRequest {
        guard let url = URL(string: path, relativeTo: baseURL) else { throw URLError(.badURL) }
        var req = URLRequest(url: url.absoluteURL)
        req.httpMethod = method
        req.timeoutInterval = timeout ?? self.timeout
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if let body { req.httpBody = try JSONEncoder().encode(AnyEncodable(body)) }
        return req
    }

    func call<T: Decodable>(_ method: String, _ path: String, body: Encodable? = nil, as: T.Type = T.self) async throws -> T {
        let (data, http) = try await transport.send(try makeRequest(method, path, body: body))
        try Self.check(http.statusCode, data)
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw SecureAIError(status: http.statusCode, code: "unreadable_reply", message: "Secure AI's answer could not be read: \(error.localizedDescription)") }
    }

    /// Errors come back in OpenAI's shape: `{ error: { message, code } }`.
    static func check(_ status: Int, _ data: Data) throws {
        guard !(200..<300).contains(status) else { return }
        let err = (try? JSONDecoder().decode(JSONValue.self, from: data))?["error"]
        throw SecureAIError(
            status: status,
            code: err?["code"]?.stringValue,
            message: err?["message"]?.stringValue ?? "Secure AI returned \(status)."
        )
    }

    /* ── Text ─────────────────────────────────────────────────────────── */

    /// Take the people out of a piece of text.
    ///
    /// Pass the map from an earlier call to keep the same stand-in for the
    /// same person across a conversation. `allow` is sent as written.
    public func redact(_ text: String, map: RedactionMap? = nil, allow: [String]? = nil, strict: Bool = false) async throws -> Redaction {
        struct Body: Encodable { let text: String; let map: RedactionMap?; let allow: [String]?; let strict: Bool? }
        return try await call("POST", "/v1/redact", body: Body(text: text, map: map, allow: allow, strict: strict ? true : nil))
    }

    /// Put the real values back into an answer.
    public func restore(_ text: String, map: RedactionMap) async throws -> String {
        struct Body: Encodable { let text: String; let map: RedactionMap }
        struct Reply: Decodable { let text: String }
        return try await call("POST", "/v1/restore", body: Body(text: text, map: map), as: Reply.self).text
    }

    /* ── Chat ─────────────────────────────────────────────────────────── */

    struct ChatBody: Encodable {
        let model: String?
        let messages: [ChatMessage]
        let stream: Bool
        let allow: [String]?
    }

    func chatRequest(_ messages: [ChatMessage], model: String?, using access: ModelAccess, stream: Bool, allow: [String]?) throws -> URLRequest {
        var headers: [String: String] = [:]
        let path: String
        switch access {
        case .secureAI:
            path = "/v1/chat/completions"
        case .yourKey(let key, let provider):
            // The proxy has no automatic choice: picking a model is picking a
            // price, and with your key the price is yours.
            guard model?.isEmpty == false else {
                throw SecureAIError(status: 400, code: "model_required", message: "Name the model when using your own key.")
            }
            path = "/v1/proxy/chat/completions"
            headers["X-Provider-Key"] = key
            if let provider { headers["X-Provider"] = provider }
        }
        return try makeRequest("POST", path, body: ChatBody(model: model, messages: messages, stream: stream, allow: allow),
                               headers: headers, timeout: Self.chatTimeout)
    }

    /// Ask a model, privately. The answer comes back with the real names in it.
    public func chat(_ messages: [ChatMessage], model: String? = nil, using access: ModelAccess = .secureAI,
                     allow: [String]? = nil) async throws -> ChatReply {
        let (data, http) = try await transport.send(try chatRequest(messages, model: model, using: access, stream: false, allow: allow))
        try Self.check(http.statusCode, data)
        let raw = try JSONDecoder().decode(JSONValue.self, from: data)
        let choice: JSONValue? = { if case .array(let a)? = raw["choices"] { return a.first }; return nil }()
        return ChatReply(
            text: choice?["message"]?["content"]?.stringValue ?? "",
            model: raw["model"]?.stringValue ?? model ?? "",
            finishReason: choice?["finish_reason"]?.stringValue,
            raw: raw
        )
    }

    /// One question, one answer.
    public func chat(_ prompt: String, model: String? = nil, using access: ModelAccess = .secureAI) async throws -> String {
        try await chat([.user(prompt)], model: model, using: access).text
    }

    /// The answer as it is written, a piece at a time. Real values are put
    /// back before each piece leaves Secure AI, so no piece holds a stand-in.
    ///
    ///     for try await piece in sai.stream([.user(question)]) { label.text += piece }
    public func stream(_ messages: [ChatMessage], model: String? = nil, using access: ModelAccess = .secureAI,
                       allow: [String]? = nil) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let req = try chatRequest(messages, model: model, using: access, stream: true, allow: allow)
                    let (lines, http) = try await transport.lines(req)
                    if !(200..<300).contains(http.statusCode) {
                        var body = ""
                        for try await line in lines { body += line }
                        try Self.check(http.statusCode, Data(body.utf8))
                    }
                    for try await line in lines {
                        guard line.hasPrefix("data:") else { continue }
                        let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                        if payload == "[DONE]" { break }
                        guard let event = try? JSONDecoder().decode(JSONValue.self, from: Data(payload.utf8)) else { continue }
                        if let err = event["error"] {
                            throw SecureAIError(status: 502, code: err["code"]?.stringValue,
                                                message: err["message"]?.stringValue ?? "The answer stopped part way.")
                        }
                        if case .array(let choices)? = event["choices"],
                           let piece = choices.first?["delta"]?["content"]?.stringValue, !piece.isEmpty {
                            continuation.yield(piece)
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Balance and this month's requests, so a long job can check first.
    public func usage() async throws -> Usage {
        try await call("GET", "/v1/usage")
    }

    /* ── Actions ──────────────────────────────────────────────────────── */

    struct InspectBody<Input: Encodable>: Encodable {
        let tool: String
        let input: Input
        let direction: Direction
        let agent: String?
        let approvalId: String?
    }

    /// Judge an action without taking it.
    public func inspect<Input: Codable & Sendable>(tool: String, input: Input, direction: Direction = .outbound,
                                                    agent: String? = nil, approvalId: String? = nil) async throws -> Inspection<Input> {
        try await call("POST", "/v1/inspect", body: InspectBody(tool: tool, input: input, direction: direction,
                                                              agent: agent ?? self.agent, approvalId: approvalId))
    }

    /// One held action.
    public func approval(_ id: String) async throws -> Approval {
        struct Reply: Decodable { let approval: Approval }
        let safe = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(["/"])) ?? id
        return try await call("GET", "/v1/approvals/\(safe)", as: Reply.self).approval
    }

    /// Wait for a person to decide. Stops at the approval's own expiry.
    public func waitForApproval(_ id: String, every seconds: TimeInterval = 2) async throws -> Approval {
        let pause = max(seconds, 0.25)
        while true {
            let a = try await approval(id)
            if a.status != .pending { return a }
            if Date().timeIntervalSince1970 * 1000 >= a.expiresAt { return Approval(copying: a, status: .expired) }
            try await Task.sleep(nanoseconds: UInt64(pause * 1_000_000_000))
        }
    }

    /// Wrap something your agent does, so it cannot run unchecked.
    ///
    /// The wrapped closure is called with the **rewritten** input — the
    /// stand-ins, not the caller's values — and is never called when the
    /// policy refuses; `ActionBlocked` is thrown instead. An action the
    /// policy holds for a person waits for them, unless `waitForApproval`
    /// is false.
    ///
    ///     let send = sai.guard("email.send") { (mail: Mail) in try await mailer.send(mail) }
    ///     try await send(Mail(to: "ana@clientfirm.com", body: "…"))
    public func `guard`<Input: Codable & Sendable, Output>(
        _ tool: String,
        direction: Direction = .outbound,
        agent: String? = nil,
        waitForApproval: Bool = true,
        _ action: @escaping @Sendable (Input) async throws -> Output
    ) -> @Sendable (Input) async throws -> Output {
        { [self] input in
            let verdict: Inspection<Input>
            do {
                verdict = try await inspect(tool: tool, input: input, direction: direction, agent: agent)
            } catch let error as SecureAIError {
                // An answer — no key, over the allowance — is never an outage.
                throw error
            } catch {
                if whenUnreachable == .open, error is URLError { return try await action(input) }
                throw error
            }

            if verdict.decision == .block { throw blocked(tool, verdict) }

            if verdict.decision == .approve {
                guard let id = verdict.approvalId, !id.isEmpty else { throw blocked(tool, verdict) }
                guard waitForApproval else { throw ApprovalRefused(tool: tool, approvalId: id, status: .pending, note: nil) }
                let decided = try await self.waitForApproval(id)
                guard decided.status == .approved else {
                    throw ApprovalRefused(tool: tool, approvalId: id, status: decided.status, note: decided.note)
                }
                // Back with the id; the server checks it is the same action.
                let after = try await inspect(tool: tool, input: input, direction: direction, agent: agent, approvalId: id)
                if after.decision == .block { throw blocked(tool, after) }
                return try await action(try sendable(tool, after, input))
            }

            return try await action(try sendable(tool, verdict, input))
        }
    }

    func blocked<I>(_ tool: String, _ v: Inspection<I>) -> ActionBlocked {
        ActionBlocked(tool: tool, findings: v.findings, toolDenied: v.toolDenied, auditId: v.auditId)
    }

    /// What may be handed to the action. Asks which decisions may send rather
    /// than which may not, so a decision added later is refused by a client
    /// that has never heard of it instead of waved through. And a redact
    /// with nothing to send never falls back to the caller's input: that is
    /// the one thing the decision said must not go.
    func sendable<I>(_ tool: String, _ v: Inspection<I>, _ original: I) throws -> I {
        guard v.decision == .allow || v.decision == .redact else {
            throw SecureAIError(status: 502, code: "unknown_decision",
                                message: "Secure AI answered \"\(v.decision)\" for \(tool), which this version does not know how to send safely. Nothing was sent. Update the SecureAI package.")
        }
        if let input = v.input { return input }
        if v.decision == .redact {
            throw SecureAIError(status: 502, code: "missing_rewritten_input",
                                message: "Secure AI decided to redact \(tool) but returned nothing to send. The original was not sent.")
        }
        return original
    }
}

/// Lets `makeRequest` take any Encodable body.
struct AnyEncodable: Encodable {
    let value: Encodable
    init(_ value: Encodable) { self.value = value }
    func encode(to encoder: Encoder) throws { try value.encode(to: encoder) }
}
