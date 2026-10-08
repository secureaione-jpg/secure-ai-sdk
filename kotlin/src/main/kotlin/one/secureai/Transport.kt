package one.secureai

import java.io.BufferedReader
import java.io.Closeable
import java.net.HttpURLConnection
import java.net.URI

class HttpRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String>,
    val body: String?,
    val timeoutMillis: Int,
)

class HttpResponse(val status: Int, val body: String)

/** A response read a line at a time, for streamed answers. */
class StreamedResponse(val status: Int, val lines: Sequence<String>, private val onClose: () -> Unit = {}) : Closeable {
    override fun close() = onClose()
}

/**
 * How requests leave the app. Blocking: the client calls it off the main
 * thread. HttpURLConnection by default, because it is on every Android and
 * every JVM with nothing to add; hand in your own to use OkHttp.
 */
interface Transport {
    fun send(request: HttpRequest): HttpResponse
    fun open(request: HttpRequest): StreamedResponse
}

class UrlConnectionTransport : Transport {
    private fun connect(r: HttpRequest): HttpURLConnection {
        val c = URI(r.url).toURL().openConnection() as HttpURLConnection
        c.requestMethod = r.method
        c.connectTimeout = r.timeoutMillis
        c.readTimeout = r.timeoutMillis
        r.headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
        if (r.body != null) {
            c.doOutput = true
            c.outputStream.use { it.write(r.body.toByteArray(Charsets.UTF_8)) }
        }
        return c
    }

    private fun HttpURLConnection.reader(): BufferedReader =
        ((if (responseCode >= 400) errorStream else inputStream) ?: "".byteInputStream()).bufferedReader(Charsets.UTF_8)

    override fun send(request: HttpRequest): HttpResponse {
        val c = connect(request)
        try {
            return HttpResponse(c.responseCode, c.reader().use { it.readText() })
        } finally {
            c.disconnect()
        }
    }

    override fun open(request: HttpRequest): StreamedResponse {
        val c = connect(request)
        val reader = c.reader()
        return StreamedResponse(c.responseCode, reader.lineSequence()) { reader.close(); c.disconnect() }
    }
}
