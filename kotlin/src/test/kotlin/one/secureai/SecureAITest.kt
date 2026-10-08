package one.secureai

import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.ConnectException

/** Answers from a script, and remembers what it was asked. */
class FakeTransport(vararg replies: Pair<Int, String>) : Transport {
    val queue = ArrayDeque(replies.toList())
    val asked = mutableListOf<HttpRequest>()
    var unreachable = false

    private fun next(r: HttpRequest): Pair<Int, String> {
        asked += r
        if (unreachable) throw ConnectException("no route")
        return queue.removeFirstOrNull() ?: (500 to "{}")
    }

    override fun send(request: HttpRequest) = next(request).let { HttpResponse(it.first, it.second) }
    override fun open(request: HttpRequest) = next(request).let { (s, b) -> StreamedResponse(s, b.lineSequence()) }

    fun path(i: Int) = asked[i].url.removePrefix("https://secureai.one")
    fun body(i: Int) = Json.read(asked[i].body!!).obj()!!
}

class SecureAITest {
    private fun client(t: FakeTransport, open: Boolean = false) =
        SecureAI("sai_test", agent = "phone-app", transport = t,
            whenUnreachable = if (open) SecureAI.WhenUnreachable.OPEN else SecureAI.WhenUnreachable.CLOSED)

    @Test fun redactSendsKeyAndReadsMap() = runBlocking {
        val t = FakeTransport(200 to """{"object":"redaction","text":"Email Sylvie","map":{"Sylvie":"Sara"},"redacted":1,"names_decided":true}""")
        val r = client(t).redact("Email Sara")
        assertEquals("Email Sylvie", r.text)
        assertEquals(mapOf("Sylvie" to "Sara"), r.map)
        assertEquals("/v1/redact", t.path(0))
        assertEquals("Bearer sai_test", t.asked[0].headers["Authorization"])
        assertEquals("Email Sara", t.body(0)["text"])
        assertFalse("unset options are left out", t.body(0).containsKey("strict"))
    }

    @Test fun restore() = runBlocking {
        val t = FakeTransport(200 to """{"text":"I emailed Sara.","restored":1}""")
        assertEquals("I emailed Sara.", client(t).restore("I emailed Sylvie.", mapOf("Sylvie" to "Sara")))
        assertEquals(mapOf("Sylvie" to "Sara"), t.body(0)["map"])
    }

    @Test fun chatWithOurModels() = runBlocking {
        val t = FakeTransport(200 to """{"model":"secureai-auto","choices":[{"message":{"role":"assistant","content":"Dear Sara"},"finish_reason":"stop"}]}""")
        val reply = client(t).chat(listOf(ChatMessage.user("Write to Sara")))
        assertEquals("Dear Sara", reply.text)
        assertEquals("stop", reply.finishReason)
        assertEquals("/v1/chat/completions", t.path(0))
        assertNull(t.asked[0].headers["X-Provider-Key"])
        assertFalse("no model means we choose", t.body(0).containsKey("model"))
    }

    @Test fun chatWithYourKeyGoesThroughTheProxy() = runBlocking {
        val t = FakeTransport(200 to """{"choices":[{"message":{"content":"Hi"}}]}""")
        assertEquals("Hi", client(t).chat("Hi", "claude-sonnet-5", ModelAccess.YourKey("sk-ant-x", "anthropic")))
        assertEquals("/v1/proxy/chat/completions", t.path(0))
        assertEquals("sk-ant-x", t.asked[0].headers["X-Provider-Key"])
        assertEquals("anthropic", t.asked[0].headers["X-Provider"])
    }

    @Test fun yourKeyNeedsAModel() = runBlocking {
        val t = FakeTransport()
        try { client(t).chat("Hi", using = ModelAccess.YourKey("sk")); fail("should throw") }
        catch (e: SecureAIException) { assertEquals("model_required", e.code) }
        assertTrue("nothing is sent", t.asked.isEmpty())
    }

    @Test fun streamYieldsPieces() = runBlocking {
        val t = FakeTransport(200 to """
            data: {"choices":[{"delta":{"role":"assistant"}}]}

            data: {"choices":[{"delta":{"content":"Dear "}}]}
            : keep-alive
            data: {"choices":[{"delta":{"content":"Sara"}}]}
            data: [DONE]
            data: {"choices":[{"delta":{"content":"after done"}}]}
        """.trimIndent())
        assertEquals("Dear Sara", client(t).stream(listOf(ChatMessage.user("x"))).toList().joinToString(""))
        assertEquals(true, t.body(0)["stream"])
    }

    @Test fun streamErrorStatusThrows() = runBlocking {
        val t = FakeTransport(402 to """{"error":{"message":"Out of balance","code":"insufficient_balance"}}""")
        try { client(t).stream(listOf(ChatMessage.user("x"))).toList(); fail("should throw") }
        catch (e: SecureAIException) { assertEquals(402, e.status); assertEquals("insufficient_balance", e.code) }
    }

    @Test fun errorsCarryStatusAndCode() = runBlocking {
        val t = FakeTransport(402 to """{"error":{"message":"Free allowance used","type":"insufficient_quota","code":"free_limit"}}""")
        try { client(t).redact("x"); fail("should throw") }
        catch (e: SecureAIException) { assertEquals(402, e.status); assertEquals("free_limit", e.code); assertEquals("Free allowance used", e.message) }
    }

    /* ── guard ── */

    private val mail = mapOf<String, Any?>("to" to "ana@client.com", "body" to "hi")

    @Test fun guardCallsWithTheRewrittenInput() = runBlocking {
        val t = FakeTransport(200 to """{"decision":"redact","input":{"to":"stand@in.com","body":"hi"},"map":{"stand@in.com":"ana@client.com"},"findings":[{"kind":"email","path":"to","decision":"redact"}],"toolDenied":false,"auditId":"a1"}""")
        var got: Map<String, Any?>? = null
        val send = client(t).guard("email.send") { got = it; true }
        assertTrue(send(mail))
        assertEquals("stand@in.com", got!!["to"])
        assertEquals("email.send", t.body(0)["tool"])
        assertEquals("phone-app", t.body(0)["agent"])
        assertEquals("outbound", t.body(0)["direction"])
    }

    @Test fun blockNeverCalls() = runBlocking {
        val t = FakeTransport(200 to """{"decision":"block","map":{},"findings":[{"kind":"card","path":"body","decision":"block"}],"auditId":"a2"}""")
        var called = false
        try { client(t).guard("email.send") { called = true }(mail); fail("should throw") }
        catch (e: ActionBlocked) { assertEquals("a2", e.auditId); assertTrue(e.message!!.contains("card at body")) }
        assertFalse(called)
    }

    @Test fun redactWithoutInputRefusesRatherThanSendingTheOriginal() = runBlocking {
        val t = FakeTransport(200 to """{"decision":"redact","map":{},"findings":[],"auditId":"a3"}""")
        var called = false
        try { client(t).guard("email.send") { called = true }(mail); fail("should throw") }
        catch (e: SecureAIException) { assertEquals("missing_rewritten_input", e.code) }
        assertFalse(called)
    }

    @Test fun unknownDecisionIsNotSent() = runBlocking {
        val t = FakeTransport(200 to """{"decision":"quarantine","input":{"to":"a"},"map":{},"findings":[],"auditId":"a4"}""")
        var called = false
        try { client(t).guard("email.send") { called = true }(mail); fail("should throw") }
        catch (e: SecureAIException) { assertEquals("unknown_decision", e.code) }
        assertFalse(called)
    }

    @Test fun allowWithoutInputSendsTheOriginal() = runBlocking {
        val t = FakeTransport(200 to """{"decision":"allow","map":{},"findings":[],"auditId":"a5"}""")
        var got: Map<String, Any?>? = null
        client(t).guard("email.send") { got = it }(mail)
        assertEquals(mail, got)
    }

    @Test fun approvalWaitsThenRechecksWithTheId() = runBlocking {
        val future = System.currentTimeMillis() + 60_000
        val t = FakeTransport(
            200 to """{"decision":"approve","approvalId":"ap1","map":{},"findings":[],"auditId":"a6"}""",
            200 to """{"approval":{"id":"ap1","status":"approved","tool":"email.send","expiresAt":$future}}""",
            200 to """{"decision":"allow","input":{"to":"a","body":"b"},"map":{},"findings":[],"auditId":"a7"}""",
        )
        var got: Map<String, Any?>? = null
        client(t).guard("email.send") { got = it }(mail)
        assertEquals(mapOf("to" to "a", "body" to "b"), got)
        assertEquals(listOf("/v1/inspect", "/v1/approvals/ap1", "/v1/inspect"), t.asked.indices.map { t.path(it) })
        assertEquals("ap1", t.body(2)["approvalId"])
    }

    @Test fun deniedApprovalThrowsWithTheNote() = runBlocking {
        val t = FakeTransport(
            200 to """{"decision":"approve","approvalId":"ap2","map":{},"findings":[],"auditId":"a8"}""",
            200 to """{"approval":{"id":"ap2","status":"denied","tool":"pay","expiresAt":1,"note":"wrong customer"}}""",
        )
        try { client(t).guard("pay") { fail("must not run") }(mail); fail("should throw") }
        catch (e: ApprovalRefused) { assertEquals("denied", e.status); assertEquals("wrong customer", e.note) }
    }

    @Test fun missingExpiryCountsAsExpired() = runBlocking {
        val t = FakeTransport(200 to """{"approval":{"id":"ap3","status":"pending","tool":"pay"}}""")
        assertEquals("expired", client(t).waitForApproval("ap3").status)
        assertEquals("does not poll forever", 1, t.asked.size)
    }

    @Test fun unreachableIsClosedByDefault() = runBlocking {
        val t = FakeTransport().apply { unreachable = true }
        var called = false
        try { client(t).guard("email.send") { called = true }(mail); fail("should throw") } catch (e: ConnectException) {}
        assertFalse(called)
    }

    @Test fun unreachableOpenGoesAhead() = runBlocking {
        val t = FakeTransport().apply { unreachable = true }
        var got: Map<String, Any?>? = null
        client(t, open = true).guard("email.send") { got = it }(mail)
        assertEquals(mail, got)
    }

    @Test fun openStillHonoursARefusal() = runBlocking {
        val t = FakeTransport(401 to """{"error":{"message":"Bad key","code":"invalid_api_key"}}""")
        var called = false
        try { client(t, open = true).guard("email.send") { called = true }(mail); fail("should throw") }
        catch (e: SecureAIException) { assertEquals(401, e.status) }
        assertFalse(called)
    }

    @Test fun defaultsToTheDocumentedAddress() {
        assertEquals("https://secureai.one/v1/usage", SecureAI("sai_x").request("GET", "/v1/usage").url)
    }

    @Test fun jsonRoundTrips() {
        val v = mapOf("a" to listOf(1L, 2.5, "x\"y\n", null, true), "b" to mapOf("c" to "é ☃"))
        assertEquals(v, Json.read(Json.write(v)))
        assertEquals("\u00e9", Json.read("\"\\u00e9\""))
    }
}
