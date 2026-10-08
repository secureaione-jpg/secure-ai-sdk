import Foundation

/// The words the API uses, as the Worker spells them.
///
/// Kept as plain lists rather than closed enums so a word the Worker adds
/// later decodes instead of failing the whole reply. sdk/vocabularyDrift.test.ts
/// in the web repo reads these lines as text and checks them against the
/// Worker's own list, the same way it checks the TypeScript and Python copies.
public enum Vocabulary {
    public static let decisions = ["allow", "redact", "approve", "block"]
    public static let directions = ["outbound", "inbound"]
    public static let kinds = ["secret", "card", "iban", "ssn", "govid", "email", "phone", "address", "postcode", "name", "host"]
}

/// What the policy said about an action.
public struct Decision: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
    public init(from decoder: Decoder) throws { rawValue = try decoder.singleValueContainer().decode(String.self) }
    public func encode(to encoder: Encoder) throws { var c = encoder.singleValueContainer(); try c.encode(rawValue) }
    public var description: String { rawValue }

    public static let allow = Decision(rawValue: "allow")
    public static let redact = Decision(rawValue: "redact")
    /// Held until a person decides.
    public static let approve = Decision(rawValue: "approve")
    public static let block = Decision(rawValue: "block")
}

public enum Direction: String, Codable, Sendable {
    case outbound, inbound
}

/// One thing the scanner found: its kind and where, never its value.
public struct Finding: Codable, Hashable, Sendable {
    /// "card", "email", "name"… — see `Vocabulary.kinds`.
    public let kind: String
    /// Where in the action it sat, e.g. "body.customer.email".
    public let path: String
    public let decision: Decision
}

/// Real value → stand-in, the other way round: keyed by the stand-in. Keep
/// it for the conversation; it is the only way to turn an answer back, and it
/// is not stored on our side.
public typealias RedactionMap = [String: String]

public struct Redaction: Codable, Sendable {
    /// The text with every person in it replaced by a believable stand-in.
    public let text: String
    public let map: RedactionMap
    /// How many things were hidden.
    public let redacted: Int
    /// False when the name check could not run, so names may have gone as
    /// written. Pass `strict: true` to be refused instead.
    public let namesDecided: Bool

    enum CodingKeys: String, CodingKey {
        case text, map, redacted
        case namesDecided = "names_decided"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        text = try c.decode(String.self, forKey: .text)
        map = try c.decodeIfPresent(RedactionMap.self, forKey: .map) ?? [:]
        redacted = try c.decodeIfPresent(Int.self, forKey: .redacted) ?? map.count
        namesDecided = try c.decodeIfPresent(Bool.self, forKey: .namesDecided) ?? true
    }
}

/// The decision about one action.
public struct Inspection<Input: Decodable & Sendable>: Decodable, Sendable {
    public let decision: Decision
    /// The action, ready to send. Absent on a block: there is deliberately
    /// nothing sendable in a refusal.
    public let input: Input?
    public let map: RedactionMap
    public let findings: [Finding]
    public let toolDenied: Bool
    public let auditId: String
    /// Set when the decision is `.approve`.
    public let approvalId: String?
    /// Milliseconds since 1970.
    public let expiresAt: Double?

    enum CodingKeys: String, CodingKey {
        case decision, input, map, findings, toolDenied, auditId, approvalId, expiresAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        decision = try c.decode(Decision.self, forKey: .decision)
        input = try c.decodeIfPresent(Input.self, forKey: .input)
        map = try c.decodeIfPresent(RedactionMap.self, forKey: .map) ?? [:]
        findings = try c.decodeIfPresent([Finding].self, forKey: .findings) ?? []
        toolDenied = try c.decodeIfPresent(Bool.self, forKey: .toolDenied) ?? false
        auditId = try c.decodeIfPresent(String.self, forKey: .auditId) ?? ""
        approvalId = try c.decodeIfPresent(String.self, forKey: .approvalId)
        expiresAt = try c.decodeIfPresent(Double.self, forKey: .expiresAt)
    }
}

public struct Approval: Decodable, Sendable {
    public enum Status: String, Decodable, Sendable { case pending, approved, denied, expired }

    public let id: String
    public let status: Status
    public let tool: String
    public let agent: String?
    public let findings: [Finding]
    /// Milliseconds since 1970. Anything unreadable counts as already
    /// expired, so a wait refuses rather than polls forever.
    public let expiresAt: Double
    public let note: String?

    enum CodingKeys: String, CodingKey { case id, status, tool, agent, findings, expiresAt, note }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        status = (try? c.decode(Status.self, forKey: .status)) ?? .expired
        tool = try c.decodeIfPresent(String.self, forKey: .tool) ?? ""
        agent = try c.decodeIfPresent(String.self, forKey: .agent)
        findings = try c.decodeIfPresent([Finding].self, forKey: .findings) ?? []
        let raw = try? c.decode(Double.self, forKey: .expiresAt)
        expiresAt = (raw?.isFinite ?? false) ? raw! : 0
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }

    init(copying a: Approval, status: Status) {
        id = a.id; self.status = status; tool = a.tool; agent = a.agent
        findings = a.findings; expiresAt = a.expiresAt; note = a.note
    }
}

/* ── Chat ─────────────────────────────────────────────────────────────── */

public struct ChatMessage: Codable, Hashable, Sendable {
    public enum Role: String, Codable, Sendable { case system, user, assistant }
    public let role: Role
    public let content: String

    public init(role: Role, content: String) { self.role = role; self.content = content }
    public static func system(_ text: String) -> ChatMessage { .init(role: .system, content: text) }
    public static func user(_ text: String) -> ChatMessage { .init(role: .user, content: text) }
    public static func assistant(_ text: String) -> ChatMessage { .init(role: .assistant, content: text) }
}

/// Whose model answers.
public enum ModelAccess: Sendable {
    /// Ours, billed to your Secure AI balance. `model` may be left out and one
    /// is chosen by how hard the question is.
    case secureAI
    /// Yours: your vendor's key goes to the one call that needs it and is
    /// never stored. `provider` only when the model name doesn't say
    /// ("anthropic", "openai", "google"…).
    case yourKey(String, provider: String? = nil)
}

public struct ChatReply: Sendable {
    /// The answer, with every real value already put back.
    public let text: String
    public let model: String
    public let finishReason: String?
    /// The full reply as sent, for anything this type does not lift out.
    public let raw: JSONValue
}

public struct Usage: Decodable, Sendable {
    public let balanceUSD: Double?
    public let spentUSD: Double?
    public let remainingUSD: Double?
    public let requestsThisMonth: Int?
    public let requestsIncluded: Int?
    public let tier: String?

    enum CodingKeys: String, CodingKey {
        case balanceUSD = "balance_usd", spentUSD = "spent_usd", remainingUSD = "remaining_usd"
        case requestsThisMonth = "requests_this_month", requestsIncluded = "requests_included", tier
    }
}

/* ── Errors ───────────────────────────────────────────────────────────── */

/// The API answered, and said no: no key, out of allowance, a bad request.
/// A problem with the call, not a decision about an action.
public struct SecureAIError: Error, LocalizedError, Sendable {
    public let status: Int
    public let code: String?
    public let message: String
    public var errorDescription: String? { message }
}

/// The policy refused the action. The guarded function was not called.
public struct ActionBlocked: Error, LocalizedError, Sendable {
    public let tool: String
    public let findings: [Finding]
    public let toolDenied: Bool
    public let auditId: String

    public var errorDescription: String? {
        let what = toolDenied
            ? "the tool itself is not permitted"
            : findings.filter { $0.decision == .block }.map { "\($0.kind) at \($0.path.isEmpty ? "the input" : $0.path)" }
                .joined(separator: ", ")
        return "Secure AI refused \(tool): \(what.isEmpty ? "policy" : what)."
    }
}

/// A person said no, or nobody answered in time. Different from
/// ActionBlocked: that is a rule to change, this is a conversation to have.
public struct ApprovalRefused: Error, LocalizedError, Sendable {
    public let tool: String
    public let approvalId: String
    public let status: Approval.Status
    public let note: String?

    public var errorDescription: String? {
        status == .expired
            ? "Secure AI held \(tool) for approval and nobody answered before it expired."
            : "Secure AI held \(tool) for approval and it was refused\(note.map { ": \($0)" } ?? ".")"
    }
}
