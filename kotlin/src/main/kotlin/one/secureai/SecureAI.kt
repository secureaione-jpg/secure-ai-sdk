package one.secureai

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.URLEncoder

/**
 * The Secure AI client for Android and the JVM.
 *
 * Two jobs, and most apps want the first:
 *
 * - **Private chat.** [chat] sends a conversation to a model with every name,
 *   email, phone number and card swapped for a stand-in first, and the real
 *   ones put back in the answer. With our models, or with your own key.
 * - **Guarded actions.** [guard] wraps something your app's agent does, so it
 *   cannot run until the account's rules have looked at it.
 *
 * Every call is a suspend function and does its network work off the main
 * thread, so it is safe to call from a ViewModel's scope.
 *
 * ── Your key in an app ──
 *
 * Anything in an APK can be read out of it. Keep the key on your server and
 * point [baseUrl] at a route there that adds it, or give the key the app
 * carries a monthly spending limit (Settings → Developer).
 */
class SecureAI(
    private val apiKey: String,
    /** The origin, without `/v1`. Change it for your own server. */
    baseUrl: String = DEFAULT_BASE,
    /** Names this app's actions in the audit trail. */
    private val agent: String? = null,
    private val timeoutMillis: Int = 10_000,
    private val whenUnreachable: WhenUnreachable = WhenUnreachable.CLOSED,
    private val transport: Transport = UrlConnectionTransport(),
) {
    enum class WhenUnreachable {
        /** The action does not happen and the error is thrown. The default. */
        CLOSED,
        /** Guarded actions go ahead unchecked when Secure AI cannot be
         *  reached at all. A refusal is still a refusal. */
        OPEN,
    }

    private val base = baseUrl.trimEnd('/')

    init {
        require(apiKey.isNotEmpty()) { "SecureAI needs an apiKey." }
    }

    companion object {
        /** The address docs/api.md gives; sdk/baseUrlDrift.test.ts keeps them together. */
        const val DEFAULT_BASE = "https://secureai.one"
        private const val CHAT_TIMEOUT = 120_000
    }

    /* ── Plumbing ── */

    internal fun request(method: String, path: String, body: Any? = null,
                         extra: Map<String, String> = emptyMap(), timeout: Int = timeoutMillis) =
        HttpRequest(
            method, base + path,
            mapOf("Authorization" to "Bearer $apiKey", "Content-Type" to "application/json") + extra,
            body?.let { Json.write(it) }, timeout,
        )

    private suspend fun call(method: String, path: String, body: Any? = null): Map<String, Any?> =
        withContext(Dispatchers.IO) {
            val res = transport.send(request(method, path, body))
            check(res.status, res.body)
            try {
                Json.read(res.body).obj() ?: emptyMap()
            } catch (e: IllegalArgumentException) {
                throw SecureAIException("Secure AI's answer could not be read.", res.status, "unreadable_reply")
            }
        }

    /** Errors come back in OpenAI's shape: `{ error: { message, code } }`. */
    private fun check(status: Int, body: String) {
        if (status in 200..299) return
        val err = runCatching { Json.read(body).obj()?.get("error").obj() }.getOrNull()
        throw SecureAIException(err?.get("message") as? String ?: "Secure AI returned $status.", status, err?.get("code") as? String)
    }

    @Suppress("UNCHECKED_CAST")
    private fun strings(raw: Any?): Map<String, String> =
        (raw.obj() ?: emptyMap()).mapNotNull { (k, v) -> (v as? String)?.let { k to it } }.toMap()

    /* ── Text ── */

    /** Take the people out of a piece of text. Pass the map from an earlier
     *  call to keep the same stand-in for the same person. */
    suspend fun redact(text: String, map: Map<String, String>? = null, allow: List<String>? = null, strict: Boolean = false): Redaction {
        val body = buildMap<String, Any?> {
            put("text", text)
            map?.let { put("map", it) }
            allow?.let { put("allow", it) }
            if (strict) put("strict", true)
        }
        val r = call("POST", "/v1/redact", body)
        val m = strings(r["map"])
        return Redaction(
            text = r["text"] as? String ?: "",
            map = m,
            redacted = (r["redacted"] as? Number)?.toInt() ?: m.size,
            namesDecided = r["names_decided"] as? Boolean ?: true,
        )
    }

    /** Put the real values back into an answer. */
    suspend fun restore(text: String, map: Map<String, String>): String =
        call("POST", "/v1/restore", mapOf("text" to text, "map" to map))["text"] as? String ?: ""

    /* ── Chat ── */

    private fun chatRequest(messages: List<ChatMessage>, model: String?, access: ModelAccess, stream: Boolean, allow: List<String>?): HttpRequest {
        val body = buildMap<String, Any?> {
            model?.let { put("model", it) }
            put("messages", messages.map { mapOf("role" to it.role, "content" to it.content) })
            put("stream", stream)
            allow?.let { put("allow", it) }
        }
        return when (access) {
            is ModelAccess.SecureAI -> request("POST", "/v1/chat/completions", body, timeout = CHAT_TIMEOUT)
            is ModelAccess.YourKey -> {
                // No automatic choice with your key: picking a model is picking a price.
                if (model.isNullOrEmpty()) throw SecureAIException("Name the model when using your own key.", 400, "model_required")
                val extra = mutableMapOf("X-Provider-Key" to access.key)
                access.provider?.let { extra["X-Provider"] = it }
                request("POST", "/v1/proxy/chat/completions", body, extra, CHAT_TIMEOUT)
            }
        }
    }

    /** Ask a model, privately. The answer comes back with the real names in it. */
    suspend fun chat(messages: List<ChatMessage>, model: String? = null, using: ModelAccess = ModelAccess.SecureAI,
                     allow: List<String>? = null): ChatReply = withContext(Dispatchers.IO) {
        val req = chatRequest(messages, model, using, false, allow)
        val res = transport.send(req)
        check(res.status, res.body)
        val raw = runCatching { Json.read(res.body).obj() }.getOrNull()
            ?: throw SecureAIException("Secure AI's answer could not be read.", res.status, "unreadable_reply")
        val choice = raw["choices"].list()?.firstOrNull().obj()
        ChatReply(
            text = choice?.get("message").obj()?.get("content") as? String ?: "",
            model = raw["model"] as? String ?: model.orEmpty(),
            finishReason = choice?.get("finish_reason") as? String,
            raw = raw,
        )
    }

    /** One question, one answer. */
    suspend fun chat(prompt: String, model: String? = null, using: ModelAccess = ModelAccess.SecureAI): String =
        chat(listOf(ChatMessage.user(prompt)), model, using).text

    /**
     * The answer as it is written, a piece at a time. Real values are put back
     * before each piece leaves Secure AI, so no piece holds a stand-in.
     *
     *     sai.stream(listOf(ChatMessage.user(q))).collect { text += it }
     */
    fun stream(messages: List<ChatMessage>, model: String? = null, using: ModelAccess = ModelAccess.SecureAI,
               allow: List<String>? = null): Flow<String> = flow {
        val res = transport.open(chatRequest(messages, model, using, true, allow))
        res.use {
            if (res.status !in 200..299) check(res.status, res.lines.joinToString(""))
            for (line in res.lines) {
                if (!line.startsWith("data:")) continue
                val payload = line.substring(5).trim()
                if (payload == "[DONE]") break
                val event = runCatching { Json.read(payload).obj() }.getOrNull() ?: continue
                event["error"].obj()?.let { err ->
                    throw SecureAIException(err["message"] as? String ?: "The answer stopped part way.", 502, err["code"] as? String)
                }
                val piece = event["choices"].list()?.firstOrNull().obj()?.get("delta").obj()?.get("content") as? String
                if (!piece.isNullOrEmpty()) emit(piece)
            }
        }
    }.flowOn(Dispatchers.IO)

    /** Balance and this month's requests, so a long job can check first. */
    suspend fun usage(): Usage {
        val r = call("GET", "/v1/usage")
        return Usage(
            (r["balance_usd"] as? Number)?.toDouble(), (r["spent_usd"] as? Number)?.toDouble(),
            (r["remaining_usd"] as? Number)?.toDouble(), (r["requests_this_month"] as? Number)?.toLong(),
            (r["requests_included"] as? Number)?.toLong(), r["tier"] as? String,
        )
    }

    /* ── Actions ── */

    /** Judge an action without taking it. */
    suspend fun inspect(tool: String, input: Any?, direction: Direction = Direction.OUTBOUND,
                        agent: String? = null, approvalId: String? = null): Inspection {
        val body = buildMap<String, Any?> {
            put("tool", tool); put("input", input); put("direction", direction.wire)
            (agent ?: this@SecureAI.agent)?.let { put("agent", it) }
            approvalId?.let { put("approvalId", it) }
        }
        val r = call("POST", "/v1/inspect", body)
        return Inspection(
            decision = r["decision"] as? String ?: "",
            input = r["input"],
            hasInput = r.containsKey("input") && r["input"] != null,
            map = strings(r["map"]),
            findings = Finding.from(r["findings"]),
            toolDenied = r["toolDenied"] as? Boolean ?: false,
            auditId = r["auditId"] as? String ?: "",
            approvalId = r["approvalId"] as? String,
            expiresAt = (r["expiresAt"] as? Number)?.toLong(),
        )
    }

    /** One held action. */
    suspend fun approval(id: String): Approval =
        Approval.from(call("GET", "/v1/approvals/" + URLEncoder.encode(id, "UTF-8").replace("+", "%20"))["approval"])

    /** Wait for a person to decide. Stops at the approval's own expiry. */
    suspend fun waitForApproval(id: String, everyMillis: Long = 2_000): Approval {
        while (true) {
            val a = approval(id)
            if (a.status != "pending") return a
            if (System.currentTimeMillis() >= a.expiresAt) return a.copy(status = "expired")
            delay(maxOf(everyMillis, 250))
        }
    }

    /**
     * Wrap something your agent does, so it cannot run unchecked.
     *
     * The wrapped function is called with the **rewritten** input — stand-ins,
     * not the caller's values — and never when the policy refuses:
     * [ActionBlocked] is thrown instead. An action held for a person waits for
     * them unless [waitForApproval] is false.
     *
     *     val send = sai.guard("email.send") { mail -> mailer.send(mail) }
     *     send(mapOf("to" to "ana@clientfirm.com", "body" to "…"))
     */
    fun <R> guard(
        tool: String,
        direction: Direction = Direction.OUTBOUND,
        agent: String? = null,
        waitForApproval: Boolean = true,
        action: suspend (Map<String, Any?>) -> R,
    ): suspend (Map<String, Any?>) -> R = { input ->
        val verdict = try {
            inspect(tool, input, direction, agent)
        } catch (e: SecureAIException) {
            throw e // an answer — no key, over the allowance — is never an outage
        } catch (e: IOException) {
            if (whenUnreachable == WhenUnreachable.OPEN) null else throw e
        }

        when {
            verdict == null -> action(input)
            verdict.decision == Decision.BLOCK -> throw blocked(tool, verdict)
            verdict.decision == Decision.APPROVE -> {
                val id = verdict.approvalId?.takeIf { it.isNotEmpty() } ?: throw blocked(tool, verdict)
                if (!waitForApproval) throw ApprovalRefused(tool, id, "pending", null)
                val decided = waitForApproval(id)
                if (decided.status != "approved") throw ApprovalRefused(tool, id, decided.status, decided.note)
                // Back with the id; the server checks it is the same action.
                val after = inspect(tool, input, direction, agent, id)
                if (after.decision == Decision.BLOCK) throw blocked(tool, after)
                action(sendable(tool, after, input))
            }
            else -> action(sendable(tool, verdict, input))
        }
    }

    private fun blocked(tool: String, v: Inspection) = ActionBlocked(tool, v.findings, v.toolDenied, v.auditId)

    /**
     * What may be handed to the action. Asks which decisions may send rather
     * than which may not, so a decision added later is refused by a client
     * that has never heard of it. A redact with nothing to send never falls
     * back to the caller's input: that is what the decision said must not go.
     */
    private fun sendable(tool: String, v: Inspection, original: Map<String, Any?>): Map<String, Any?> {
        if (v.decision != Decision.ALLOW && v.decision != Decision.REDACT) {
            throw SecureAIException(
                "Secure AI answered \"${v.decision}\" for $tool, which this version does not know how to send safely. " +
                    "Nothing was sent. Update one.secureai:secure-ai.", 502, "unknown_decision",
            )
        }
        v.input.obj()?.let { return it }
        if (v.decision == Decision.REDACT) {
            throw SecureAIException(
                "Secure AI decided to redact $tool but returned nothing to send. The original was not sent.",
                502, "missing_rewritten_input",
            )
        }
        return original
    }
}
