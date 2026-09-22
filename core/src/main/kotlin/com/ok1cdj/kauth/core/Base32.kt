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
 * RFC 4648 Base32 — the encoding used for `otpauth://` secrets.
 *
 * [decode] is deliberately lenient, because real-world secrets are pasted by
 * humans: it ignores ASCII whitespace and `=` padding, and accepts either case.
 * [encode] produces upper-case output without padding, the form used in
 * `otpauth://` URIs. Anything outside the alphabet is a hard error.
 */
object Base32 {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    private val REVERSE = IntArray(128) { -1 }.also { table ->
        for (i in ALPHABET.indices) {
            table[ALPHABET[i].code] = i
            table[ALPHABET[i].lowercaseChar().code] = i
        }
    }

    /** Decode a Base32 string to bytes. Throws [IllegalArgumentException] on any
     *  character that is not Base32, whitespace or padding. */
    fun decode(input: String): ByteArray {
        var buffer = 0
        var bitsLeft = 0
        val out = ArrayList<Byte>(input.length * 5 / 8 + 1)
        for (c in input) {
            if (c == '=' || c == ' ' || c == '\t' || c == '\n' || c == '\r') continue
            val value = if (c.code < 128) REVERSE[c.code] else -1
            require(value >= 0) { "not a Base32 character: '$c'" }
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                out.add(((buffer shr bitsLeft) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }

    /** Encode bytes to an upper-case, unpadded Base32 string. */
    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val sb = StringBuilder(data.size * 8 / 5 + 1)
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                bitsLeft -= 5
                sb.append(ALPHABET[(buffer shr bitsLeft) and 0x1F])
            }
        }
        if (bitsLeft > 0) {
            sb.append(ALPHABET[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        return sb.toString()
    }

    /** True if [input] contains only decodable Base32 (ignoring padding/whitespace)
     *  and is non-empty — used to validate manually entered secrets. */
    fun isValid(input: String): Boolean = runCatching { decode(input).isNotEmpty() }.getOrDefault(false)
}
