package one.secureai

/**
 * Just enough JSON: objects become `Map<String, Any?>`, arrays `List<Any?>`,
 * numbers `Double` or `Long`.
 *
 * Here rather than a library for the reason the other clients have none:
 * this sits inside somebody's app beside their Gson or Moshi or
 * kotlinx.serialization, and whichever one it chose would be the wrong
 * version for somebody. A tool's input is whatever the tool takes, so a map
 * is also the honest type for it.
 */
internal object Json {
    fun write(value: Any?): String = StringBuilder().also { write(value, it) }.toString()

    private fun write(v: Any?, out: StringBuilder) {
        when (v) {
            null -> out.append("null")
            is String -> string(v, out)
            is Boolean -> out.append(v)
            is Double -> if (v.isFinite()) {
                if (v == Math.floor(v) && Math.abs(v) < 1e15) out.append(v.toLong()) else out.append(v)
            } else out.append("null")
            is Float -> write(v.toDouble(), out)
            is Number -> out.append(v)
            is Map<*, *> -> {
                out.append('{')
                var first = true
                for ((k, value) in v) {
                    if (!first) out.append(',')
                    first = false
                    string(k.toString(), out); out.append(':'); write(value, out)
                }
                out.append('}')
            }
            is Iterable<*> -> {
                out.append('[')
                v.forEachIndexed { i, item -> if (i > 0) out.append(','); write(item, out) }
                out.append(']')
            }
            is Array<*> -> write(v.toList(), out)
            else -> string(v.toString(), out)
        }
    }

    private fun string(s: String, out: StringBuilder) {
        out.append('"')
        for (c in s) when {
            c == '"' -> out.append("\\\"")
            c == '\\' -> out.append("\\\\")
            c == '\n' -> out.append("\\n")
            c == '\r' -> out.append("\\r")
            c == '\t' -> out.append("\\t")
            c < ' ' -> out.append(String.format("\\u%04x", c.code))
            else -> out.append(c)
        }
        out.append('"')
    }

    fun read(text: String): Any? {
        val p = Parser(text)
        p.space()
        val v = p.value()
        p.space()
        if (p.i != text.length) throw IllegalArgumentException("Trailing text at ${p.i}")
        return v
    }

    private class Parser(val s: String) {
        var i = 0

        fun space() { while (i < s.length && s[i].isWhitespace()) i++ }

        fun value(): Any? {
            space()
            if (i >= s.length) throw IllegalArgumentException("Unexpected end")
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> word("true", true)
                'f' -> word("false", false)
                'n' -> word("null", null)
                else -> num()
            }
        }

        fun word(w: String, v: Any?): Any? {
            if (!s.startsWith(w, i)) throw IllegalArgumentException("Bad value at $i")
            i += w.length
            return v
        }

        fun obj(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++; space()
            if (s[i] == '}') { i++; return m }
            while (true) {
                space(); val k = str(); space()
                if (s[i] != ':') throw IllegalArgumentException("Expected : at $i")
                i++
                m[k] = value(); space()
                when (s[i]) { ',' -> i++; '}' -> { i++; return m }; else -> throw IllegalArgumentException("Expected , or } at $i") }
            }
        }

        fun arr(): List<Any?> {
            val l = ArrayList<Any?>()
            i++; space()
            if (s[i] == ']') { i++; return l }
            while (true) {
                l.add(value()); space()
                when (s[i]) { ',' -> i++; ']' -> { i++; return l }; else -> throw IllegalArgumentException("Expected , or ] at $i") }
            }
        }

        fun str(): String {
            if (s[i] != '"') throw IllegalArgumentException("Expected string at $i")
            i++
            val b = StringBuilder()
            while (true) {
                val c = s[i++]
                when (c) {
                    '"' -> return b.toString()
                    '\\' -> when (val e = s[i++]) {
                        'n' -> b.append('\n'); 't' -> b.append('\t'); 'r' -> b.append('\r')
                        'b' -> b.append('\b'); 'f' -> b.append('\u000c')
                        'u' -> { b.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                        else -> b.append(e)
                    }
                    else -> b.append(c)
                }
            }
        }

        fun num(): Number {
            val start = i
            while (i < s.length && (s[i].isDigit() || s[i] in "+-.eE")) i++
            val t = s.substring(start, i)
            if (t.isEmpty()) throw IllegalArgumentException("Bad value at $start")
            return if (t.any { it in ".eE" }) t.toDouble() else t.toLongOrNull() ?: t.toDouble()
        }
    }
}

@Suppress("UNCHECKED_CAST")
internal fun Any?.obj(): Map<String, Any?>? = this as? Map<String, Any?>
internal fun Any?.list(): List<Any?>? = this as? List<Any?>
