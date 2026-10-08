package one.secureai

/**
 * The words the API uses, as the Worker spells them. Plain strings rather
 * than enums so a word the Worker adds later is read instead of crashing the
 * reply. sdk/vocabularyDrift.test.ts in the web repo reads these three lines
 * and checks them against the Worker's own list.
 */
object Vocabulary {
    val DECISIONS = listOf("allow", "redact", "approve", "block")
    val DIRECTIONS = listOf("outbound", "inbound")
    val KINDS = listOf("secret", "card", "iban", "ssn", "govid", "email", "phone", "address", "postcode", "name", "host")
}

object Decision {
    const val ALLOW = "allow"
    const val REDACT = "redact"
    /** Held until a person decides. */
    const val APPROVE = "approve"
    const val BLOCK = "block"
}

enum class Direction(val wire: String) { OUTBOUND("outbound"), INBOUND("inbound") }

/** One thing the scanner found: its kind and where, never its value. */
data class Finding(val kind: String, val path: String, val decision: String) {
    internal companion object {
        fun from(raw: Any?): List<Finding> = raw.list().orEmpty().mapNotNull { f ->
            val m = f.obj() ?: return@mapNotNull null
            Finding(m["kind"] as? String ?: "", m["path"] as? String ?: "", m["decision"] as? String ?: "")
        }
    }
}

/**
 * Text with the people taken out. [map] is keyed by stand-in, valued by the
 * real thing. Keep it for the conversation: it is the only way to turn an
 * answer back, and it is not stored on our side.
 */
data class Redaction(
    val text: String,
    val map: Map<String, String>,
    val redacted: Int,
    /** False when the name check could not run. Pass `strict = true` to be refused instead. */
    val namesDecided: Boolean,
)

/** The decision about one action. */
data class Inspection(
    val decision: String,
    /** Ready to send. Null on a block: a refusal has nothing sendable in it. */
    val input: Any?,
    val hasInput: Boolean,
    val map: Map<String, String>,
    val findings: List<Finding>,
    val toolDenied: Boolean,
    val auditId: String,
    val approvalId: String?,
    /** Milliseconds since 1970. */
    val expiresAt: Long?,
)

data class Approval(
    val id: String,
    /** pending, approved, denied or expired. */
    val status: String,
    val tool: String,
    val agent: String?,
    val findings: List<Finding>,
    /** Milliseconds since 1970. Unreadable counts as already expired, so a
     *  wait refuses rather than polls forever. */
    val expiresAt: Long,
    val note: String?,
) {
    internal companion object {
        fun from(raw: Any?): Approval {
            val m = raw.obj() ?: emptyMap()
            val exp = (m["expiresAt"] as? Number)?.toDouble()
            return Approval(
                id = m["id"] as? String ?: "",
                status = m["status"] as? String ?: "expired",
                tool = m["tool"] as? String ?: "",
                agent = m["agent"] as? String,
                findings = Finding.from(m["findings"]),
                expiresAt = if (exp != null && exp.isFinite()) exp.toLong() else 0L,
                note = m["note"] as? String,
            )
        }
    }
}

data class ChatMessage(val role: String, val content: String) {
    companion object {
        fun system(text: String) = ChatMessage("system", text)
        fun user(text: String) = ChatMessage("user", text)
        fun assistant(text: String) = ChatMessage("assistant", text)
    }
}

/** Whose model answers. */
sealed class ModelAccess {
    /** Ours, billed to your Secure AI balance. The model may be left out. */
    object SecureAI : ModelAccess()
    /** Yours: the key goes to the one call that needs it and is never stored.
     *  [provider] only when the model name doesn't say ("anthropic", "openai"…). */
    data class YourKey(val key: String, val provider: String? = null) : ModelAccess()
}

data class ChatReply(
    /** The answer, with every real value already put back. */
    val text: String,
    val model: String,
    val finishReason: String?,
    /** The whole reply, for anything not lifted out above. */
    val raw: Map<String, Any?>,
)

data class Usage(
    val balanceUsd: Double?,
    val spentUsd: Double?,
    val remainingUsd: Double?,
    val requestsThisMonth: Long?,
    val requestsIncluded: Long?,
    val tier: String?,
)

/* ── Errors ── */

/** The API answered, and said no: no key, out of allowance, a bad request. */
class SecureAIException(message: String, val status: Int, val code: String?) : Exception(message)

/** The policy refused the action. The guarded function was not called. */
class ActionBlocked(val tool: String, val findings: List<Finding>, val toolDenied: Boolean, val auditId: String) :
    Exception(
        "Secure AI refused $tool: " + (
            if (toolDenied) "the tool itself is not permitted"
            else findings.filter { it.decision == Decision.BLOCK }
                .joinToString(", ") { "${it.kind} at ${it.path.ifEmpty { "the input" }}" }
                .ifEmpty { "policy" }
            ) + "."
    )

/** A person said no, or nobody answered in time. */
class ApprovalRefused(val tool: String, val approvalId: String, val status: String, val note: String?) :
    Exception(
        if (status == "expired") "Secure AI held $tool for approval and nobody answered before it expired."
        else "Secure AI held $tool for approval and it was refused" + (note?.let { ": $it" } ?: ".")
    )
