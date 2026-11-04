import CryptoKit
import Foundation

/// Secure mode: a conversation nobody between the app and the model can read
/// (2026-10-08). The Swift half of src/secure.ts in the TypeScript SDK.
///
/// The conversation is sealed on the device to a key that exists only inside
/// an AWS Nitro enclave, after checking AWS's signed document saying which
/// program holds it. Secure AI relays the envelope without being able to open
/// it. If the enclave cannot prove what it runs, nothing is sent — there is no
/// fallback to the ordinary path.

/// What `GET /v1/sealed` says.
public struct SealedInfo: Decodable, Sendable {
    public struct Model: Decodable, Sendable { public let id: String; public let provider: String }
    public let available: Bool
    public let enclave: String
    public let images: [String]
    public let models: [Model]
    public let defaultModel: String
    public let maxOutputTokens: Int

    enum CodingKeys: String, CodingKey {
        case available, enclave, images, models
        case defaultModel = "default_model", maxOutputTokens = "max_output_tokens"
    }
}

/// Could not send in Secure mode. `.unverified` means the enclave could not
/// prove what it runs and nothing was sent; `.unreachable` is worth retrying;
/// `.refused` is the API saying no (see `status` and `code`).
public struct SecureModeError: Error, LocalizedError, Sendable {
    public enum Reason: Sendable { case unverified, unreachable, refused }
    public let reason: Reason
    public let status: Int
    public let code: String?
    public let message: String
    public var errorDescription: String? { message }
}

/// The discovery answer and the verified key, cached for as long as the
/// attestation document is good. An actor, because two conversations started
/// at once must not each verify and race to store.
public actor SecureModeState {
    var info: SealedInfo?
    var key: (spki: Data, goodUntil: Date)?
    public init() {}
}

extension SecureAI {
    /// What Secure mode will trust and which models it offers.
    public func secureInfo() async throws -> SealedInfo {
        if let cached = await secure.info { return cached }
        let info: SealedInfo
        do {
            let (data, http) = try await transport.send(try makeRequest("GET", "/v1/sealed"))
            guard http.statusCode == 200 else { throw URLError(.badServerResponse) }
            info = try JSONDecoder().decode(SealedInfo.self, from: data)
        } catch {
            throw SecureModeError(reason: .unreachable, status: 0, code: nil, message: "Could not reach Secure AI: \(error.localizedDescription)")
        }
        await secure.setInfo(info)
        return info
    }

    func enclaveKey(_ info: SealedInfo) async throws -> Data {
        if let k = await secure.key, Date() < k.goodUntil { return k.spki }
        let nonce = "\(Int(Date().timeIntervalSince1970 * 1000))-\(UUID().uuidString)"
        var parts = URLComponents(string: info.enclave.hasSuffix("/") ? String(info.enclave.dropLast()) + "/attestation" : info.enclave + "/attestation")
        parts?.queryItems = [URLQueryItem(name: "nonce", value: nonce)]
        guard let url = parts?.url else {
            throw SecureModeError(reason: .unreachable, status: 0, code: nil, message: "The enclave's address is not usable.")
        }
        struct Doc: Decodable { let attested: Bool?; let document: String?; let reason: String? }
        let doc: Doc
        do {
            var req = URLRequest(url: url)
            req.timeoutInterval = 15
            let (data, http) = try await transport.send(req)
            guard http.statusCode == 200 else { throw URLError(.badServerResponse) }
            doc = try JSONDecoder().decode(Doc.self, from: data)
        } catch {
            throw SecureModeError(reason: .unreachable, status: 0, code: nil, message: "Could not reach the enclave: \(error.localizedDescription)")
        }
        // An unattested reply still carries a real key; a client that reads
        // the key without reading `attested` seals to something unvouched for.
        guard doc.attested == true, let document = doc.document else {
            throw SecureModeError(reason: .unverified, status: 0, code: nil, message: "The enclave is not attested: \(doc.reason ?? "no document"). Nothing was sent.")
        }
        switch Attestation.verify(documentBase64: document, nonce: nonce, trustedPCR0: trustedImages ?? info.images) {
        case .failure(let f):
            throw SecureModeError(reason: .unverified, status: 0, code: nil, message: "The enclave could not be verified: \(f). Nothing was sent.")
        case .success(let v):
            // Good while the document is, less two minutes so a request
            // started just inside the window does not finish outside it.
            let start = min(Date(timeIntervalSince1970: v.timestamp / 1000), Date())
            let until = start.addingTimeInterval(3 * 60 * 60 - 120)
            await secure.setKey(v.publicKey, until: until)
            return v.publicKey
        }
    }

    /// Ask a model with nobody in between able to read the conversation.
    ///
    ///     let answer = try await sai.secureChat([.user("Summarise Sara Whitfield's file")]) { piece in
    ///         label.text += piece
    ///     }
    ///
    /// Part of the API subscription; priced per message. `messages` take the
    /// user and assistant roles; put instructions in `system`.
    @discardableResult
    public func secureChat(_ messages: [ChatMessage], system: String? = nil, model: String? = nil,
                           onText: (@Sendable (String) -> Void)? = nil) async throws -> String {
        let info = try await secureInfo()
        guard info.available else {
            throw SecureModeError(reason: .unreachable, status: 503, code: "sealed_unavailable", message: "Secure mode is not available right now. Nothing was sent.")
        }
        let name = model ?? info.defaultModel
        guard let entry = info.models.first(where: { $0.id == name }) else {
            throw SecureModeError(reason: .refused, status: 400, code: "model_not_available",
                                  message: "Secure mode can't use \"\(name)\". Use one of: \(info.models.map(\.id).joined(separator: ", ")).")
        }
        let spki = try await enclaveKey(info)

        let request = SealedRequestBody(provider: entry.provider, model: name, maxTokens: info.maxOutputTokens,
                                        messages: messages.filter { $0.role != .system }, system: system)
        let sealed: (envelope: Envelope.Sealed, session: CryptoKitKey)
        do {
            let s = try Envelope.seal(try JSONEncoder().encode(request), to: spki)
            sealed = (s.envelope, CryptoKitKey(s.session))
        } catch {
            throw SecureModeError(reason: .unverified, status: 0, code: nil, message: "\(error). Nothing was sent.")
        }

        var req = try makeRequest("POST", "/v1/sealed/chat", body: sealed.envelope, headers: ["X-Model": name], timeout: Self.chatTimeout)
        req.setValue(String(req.httpBody?.count ?? 0), forHTTPHeaderField: "Content-Length")
        let lines: AsyncThrowingStream<String, Error>
        let http: HTTPURLResponse
        do {
            (lines, http) = try await transport.lines(req)
        } catch {
            throw SecureModeError(reason: .unreachable, status: 0, code: nil, message: "Could not reach Secure AI: \(error.localizedDescription)")
        }
        if !(200..<300).contains(http.statusCode) {
            var body = ""
            for try await line in lines { body += line }
            let err = (try? JSONDecoder().decode(JSONValue.self, from: Data(body.utf8)))?["error"]
            throw SecureModeError(reason: .refused, status: http.statusCode, code: err?["code"]?.stringValue,
                                  message: err?["message"]?.stringValue ?? "Secure AI refused this (\(http.statusCode)).")
        }

        var reader = Envelope.Reader(session: sealed.session.key)
        var text = ""
        for try await line in lines {
            guard line.hasPrefix("data:") else { continue }
            let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
            guard !payload.isEmpty else { continue }
            let piece = try JSONDecoder().decode(Envelope.Reader.Piece.self, from: Data(payload.utf8))
            let opened: String
            do { opened = try reader.open(piece) } catch {
                throw SecureModeError(reason: .refused, status: 502, code: "sealed_stream", message: "\(error)")
            }
            for delta in Self.deltas(opened, provider: entry.provider) {
                text += delta
                onText?(delta)
            }
        }
        do { try reader.finish() } catch {
            throw SecureModeError(reason: .refused, status: 502, code: "sealed_stream", message: "\(error)")
        }
        return text
    }

    /// The text in one opened piece: the provider's own stream, real values back.
    static func deltas(_ chunk: String, provider: String) -> [String] {
        chunk.split(separator: "\n").compactMap { raw -> String? in
            let line = String(raw)
            guard line.hasPrefix("data:") else { return nil }
            let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
            guard !payload.isEmpty, payload != "[DONE]",
                  let j = try? JSONDecoder().decode(JSONValue.self, from: Data(payload.utf8)) else { return nil }
            let delta: String?
            switch provider {
            case "anthropic":
                delta = j["type"]?.stringValue == "content_block_delta" && j["delta"]?["type"]?.stringValue == "text_delta"
                    ? j["delta"]?["text"]?.stringValue : nil
            case "google":
                if case .array(let c)? = j["candidates"], case .array(let parts)? = c.first?["content"]?["parts"] {
                    delta = parts.compactMap { $0["text"]?.stringValue }.joined()
                } else { delta = nil }
            default:
                if case .array(let c)? = j["choices"] { delta = c.first?["delta"]?["content"]?.stringValue } else { delta = nil }
            }
            return (delta?.isEmpty == false) ? delta : nil
        }
    }
}

extension SecureModeState {
    func setInfo(_ i: SealedInfo) { info = i }
    func setKey(_ k: Data, until: Date) { key = (k, until) }
}

/// The provider request the enclave will make, minus the conversation —
/// shaped as src/secure.ts shapes it, so both SDKs ask for the same thing.
struct SealedRequestBody: Encodable {
    let provider: String
    let model: String
    let maxTokens: Int
    let messages: [ChatMessage]
    let system: String?

    enum Keys: String, CodingKey { case provider, path, body, messages, system }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(provider == "google" || provider == "openai" ? provider : "anthropic", forKey: .provider)
        switch provider {
        case "openai":
            try c.encode("/v1/chat/completions", forKey: .path)
            try c.encode(["model": JSONValue.string(model), "stream": .bool(true), "max_completion_tokens": .number(Double(maxTokens))], forKey: .body)
        case "google":
            try c.encode("/v1beta/models/\(model):streamGenerateContent?alt=sse", forKey: .path)
            try c.encode(["generationConfig": JSONValue.object(["maxOutputTokens": .number(Double(maxTokens))])], forKey: .body)
        default:
            try c.encode("/v1/messages", forKey: .path)
            try c.encode(["model": JSONValue.string(model), "max_tokens": .number(Double(maxTokens)), "stream": .bool(true)], forKey: .body)
        }
        try c.encode(messages, forKey: .messages)
        try c.encodeIfPresent(system, forKey: .system)
    }
}

/// Carries the session key across a suspension point without exposing
/// CryptoKit in the public surface.
struct CryptoKitKey: @unchecked Sendable {
    let key: SymmetricKey
    init(_ k: SymmetricKey) { key = k }
}
