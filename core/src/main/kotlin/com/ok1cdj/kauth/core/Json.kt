/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.ok1cdj.kauth.core

/**
 * A tiny, dependency-free JSON reader/writer — enough for the fixed shapes this
 * app uses (the account list and the encrypted-vault header). No Gson/Moshi, and
 * pure JVM so it lives in :core and is unit-tested without Android.
 *
 * [parse] returns a tree of `Map<String, Any?>`, `List<Any?>`, `String`,
 * `Double`, `Boolean`, or `null`. [stringify] does the reverse for those types
 * plus `Int`/`Long`.
 */
object Json {

    fun parse(text: String): Any? = Parser(text).run {
        val v = readValue()
        skipWs()
        require(pos >= text.length) { "trailing characters at $pos" }
        v
    }

    @Suppress("UNCHECKED_CAST")
    fun parseArray(text: String): List<Any?> = parse(text) as List<Any?>

    @Suppress("UNCHECKED_CAST")
    fun parseObject(text: String): Map<String, Any?> = parse(text) as Map<String, Any?>

    fun stringify(value: Any?): String = StringBuilder().also { write(it, value) }.toString()

    private fun write(sb: StringBuilder, value: Any?) {
        when (value) {
            null -> sb.append("null")
            is Boolean -> sb.append(value)
            is Int, is Long -> sb.append(value.toString())
            is Double -> sb.append(if (value % 1.0 == 0.0) value.toLong().toString() else value.toString())
            is String -> writeString(sb, value)
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, v) in value) {
                    if (!first) sb.append(','); first = false
                    writeString(sb, k.toString()); sb.append(':'); write(sb, v)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                var first = true
                for (v in value) {
                    if (!first) sb.append(','); first = false
                    write(sb, v)
                }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("cannot serialize ${value::class}")
        }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) when (c) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
        sb.append('"')
    }

    private class Parser(val s: String) {
        var pos = 0

        fun skipWs() { while (pos < s.length && s[pos].isWhitespace()) pos++ }

        fun readValue(): Any? {
            skipWs()
            require(pos < s.length) { "unexpected end of input" }
            return when (val c = s[pos]) {
                '{' -> readObject()
                '[' -> readArray()
                '"' -> readString()
                't' -> readLiteral("true", true)
                'f' -> readLiteral("false", false)
                'n' -> readLiteral("null", null)
                else -> if (c == '-' || c.isDigit()) readNumber()
                        else throw IllegalArgumentException("unexpected '$c' at $pos")
            }
        }

        private fun readObject(): Map<String, Any?> {
            val map = LinkedHashMap<String, Any?>()
            pos++ // {
            skipWs()
            if (peek() == '}') { pos++; return map }
            while (true) {
                skipWs()
                val key = readString()
                skipWs()
                require(s[pos] == ':') { "expected ':' at $pos" }
                pos++
                map[key] = readValue()
                skipWs()
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return map }
                    else -> throw IllegalArgumentException("expected ',' or '}' at $pos")
                }
            }
        }

        private fun readArray(): List<Any?> {
            val list = ArrayList<Any?>()
            pos++ // [
            skipWs()
            if (peek() == ']') { pos++; return list }
            while (true) {
                list.add(readValue())
                skipWs()
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return list }
                    else -> throw IllegalArgumentException("expected ',' or ']' at $pos")
                }
            }
        }

        private fun readString(): String {
            require(s[pos] == '"') { "expected string at $pos" }
            pos++
            val sb = StringBuilder()
            while (true) {
                val c = s[pos++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'u' -> { sb.append(s.substring(pos, pos + 4).toInt(16).toChar()); pos += 4 }
                            else -> throw IllegalArgumentException("bad escape '\\$e' at $pos")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun readNumber(): Double {
            val start = pos
            if (peek() == '-') pos++
            while (pos < s.length && (s[pos].isDigit() || s[pos] in ".eE+-")) pos++
            return s.substring(start, pos).toDouble()
        }

        private fun <T> readLiteral(lit: String, value: T): T {
            require(s.regionMatches(pos, lit, 0, lit.length)) { "expected '$lit' at $pos" }
            pos += lit.length
            return value
        }

        private fun peek(): Char = s[pos]
    }
}
