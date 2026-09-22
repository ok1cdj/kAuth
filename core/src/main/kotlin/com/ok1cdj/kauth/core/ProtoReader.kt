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
 * A minimal protocol-buffers wire-format reader — just enough to decode the
 * Google Authenticator migration payload without pulling in the protobuf runtime.
 * Implemented from the public wire-format spec (varint / length-delimited / fixed).
 *
 * It reads (field number, wire type) tags, the four wire types, and can skip
 * unknown fields — so a payload with extra/unexpected fields decodes cleanly
 * instead of crashing. Out-of-range reads throw [IllegalStateException], which
 * the caller turns into a recorded failure rather than an app crash.
 */
class ProtoReader(private val buf: ByteArray) {

    var pos = 0
        private set

    fun hasMore(): Boolean = pos < buf.size

    /** Wire type of the last-read tag. */
    var lastWireType = 0
        private set

    /** Read a field tag, returning the field number and storing [lastWireType]. */
    fun readTag(): Int {
        val tag = readVarint()
        lastWireType = (tag and 0x7).toInt()
        return (tag ushr 3).toInt()
    }

    fun readVarint(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            check(pos < buf.size) { "varint runs past end of buffer" }
            val b = buf[pos++].toInt() and 0xFF
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            check(shift < 64) { "varint too long" }
        }
        return result
    }

    fun readLengthDelimited(): ByteArray {
        val len = readVarint().toInt()
        check(len >= 0 && pos + len <= buf.size) { "length-delimited field runs past end of buffer" }
        val out = buf.copyOfRange(pos, pos + len)
        pos += len
        return out
    }

    fun readString(): String = String(readLengthDelimited(), Charsets.UTF_8)

    /** Skip a field of the given [wireType] (from [lastWireType]). */
    fun skip(wireType: Int) {
        when (wireType) {
            0 -> readVarint()                 // varint
            1 -> advance(8)                   // 64-bit
            2 -> advance(readVarint().toInt()) // length-delimited
            5 -> advance(4)                   // 32-bit
            else -> throw IllegalStateException("unknown wire type: $wireType")
        }
    }

    private fun advance(n: Int) {
        check(n >= 0 && pos + n <= buf.size) { "skip runs past end of buffer" }
        pos += n
    }
}
