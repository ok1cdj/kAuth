/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 */

package com.ok1cdj.kauth.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.util.Base64

/**
 * Exercises the from-scratch migration decoder with payloads built by an
 * independent little protobuf encoder below (so a bug shared with the reader
 * can't hide). The key requirement under test: a malformed account must be
 * reported and skipped, never crash the whole import.
 */
class GaMigrationTest {

    @Test
    fun `decodes a two-account payload`() {
        val sha1Secret = "12345678901234567890".toByteArray(Charsets.US_ASCII)
        val sha256Secret = "abcdefghijklmnopqrst".toByteArray(Charsets.US_ASCII)
        val payload = migrationUri(
            batchSize = 1,
            batchIndex = 0,
            accounts = listOf(
                otpParams(sha1Secret, "alice", "ACME", algo = 1, digits = 1, type = 2, counter = 0),
                otpParams(sha256Secret, "bob", "Globex", algo = 2, digits = 2, type = 1, counter = 7),
            ),
        )

        val result = GaMigration.decode(payload)
        assertTrue(result.failures.isEmpty(), "no failures: ${result.failures}")
        assertEquals(2, result.accounts.size)

        val alice = result.accounts[0]
        assertEquals("ACME", alice.issuer)
        assertEquals("alice", alice.name)
        assertEquals(Base32.encode(sha1Secret), alice.secret)
        assertEquals(OtpAlgorithm.SHA1, alice.algorithm)
        assertEquals(6, alice.digits)
        assertEquals(OtpType.TOTP, alice.type)

        val bob = result.accounts[1]
        assertEquals("Globex", bob.issuer)
        assertEquals(Base32.encode(sha256Secret), bob.secret)
        assertEquals(OtpAlgorithm.SHA256, bob.algorithm)
        assertEquals(8, bob.digits)
        assertEquals(OtpType.HOTP, bob.type)
        assertEquals(7L, bob.counter)
    }

    @Test
    fun `a corrupt account is skipped and the rest import`() {
        val goodSecret = "12345678901234567890".toByteArray(Charsets.US_ASCII)
        val good = otpParams(goodSecret, "alice", "ACME", algo = 1, digits = 1, type = 2, counter = 0)

        // A chunk whose inner secret field claims length 100 but supplies 3 bytes.
        val corrupt = byteArrayOf(0x0A, 100, 0x01, 0x02, 0x03)

        val body = ByteArrayOutputStream().apply {
            writeBytes(lengthDelim(1, good))
            writeBytes(lengthDelim(1, corrupt))
            writeBytes(lengthDelim(1, good)) // a second good one after the corrupt entry
            writeBytes(varintField(3, 1))    // batch_size
            writeBytes(varintField(4, 0))    // batch_index
        }.toByteArray()

        val result = GaMigration.decode(wrap(body))
        assertEquals(2, result.accounts.size, "both good accounts import")
        assertEquals(1, result.failures.size, "the corrupt one is reported")
        assertTrue(result.failures[0].contains("#2"))
    }

    @Test
    fun `an empty secret is reported, not imported`() {
        val body = lengthDelim(1, otpParams(ByteArray(0), "x", "y", 1, 1, 2, 0))
        val result = GaMigration.decode(wrap(body))
        assertTrue(result.accounts.isEmpty())
        assertEquals(1, result.failures.size)
    }

    @Test
    fun `reads batch index and size for multi-part exports`() {
        val secret = "12345678901234567890".toByteArray(Charsets.US_ASCII)
        val body = ByteArrayOutputStream().apply {
            writeBytes(lengthDelim(1, otpParams(secret, "a", "b", 1, 1, 2, 0)))
            writeBytes(varintField(3, 3)) // batch_size = 3
            writeBytes(varintField(4, 2)) // batch_index = 2
        }.toByteArray()
        val result = GaMigration.decode(wrap(body))
        assertEquals(3, result.batchSize)
        assertEquals(2, result.batchIndex)
    }

    @Test
    fun `garbage input never throws`() {
        assertFalse(GaMigration.decode("otpauth-migration://offline?data=%%%notbase64%%%").failures.isEmpty())
        assertFalse(GaMigration.decode("otpauth-migration://offline").failures.isEmpty())
        assertTrue(GaMigration.decode("otpauth-migration://offline?data=AAAA").accounts.isEmpty())
    }

    @Test
    fun `isMigration detects the scheme`() {
        assertTrue(GaMigration.isMigration("otpauth-migration://offline?data=AAAA"))
        assertFalse(GaMigration.isMigration("otpauth://totp/a?secret=x"))
    }

    // --- minimal protobuf encoder (independent of ProtoReader) ----------------

    private fun varint(value: Long): ByteArray {
        var v = value
        val out = ByteArrayOutputStream()
        while (true) {
            val b = (v and 0x7F).toInt()
            v = v ushr 7
            if (v != 0L) out.write(b or 0x80) else { out.write(b); break }
        }
        return out.toByteArray()
    }

    private fun tag(field: Int, wire: Int): ByteArray = varint(((field shl 3) or wire).toLong())

    private fun lengthDelim(field: Int, bytes: ByteArray): ByteArray =
        ByteArrayOutputStream().apply {
            writeBytes(tag(field, 2))
            writeBytes(varint(bytes.size.toLong()))
            writeBytes(bytes)
        }.toByteArray()

    private fun varintField(field: Int, value: Long): ByteArray =
        ByteArrayOutputStream().apply {
            writeBytes(tag(field, 0))
            writeBytes(varint(value))
        }.toByteArray()

    private fun otpParams(
        secret: ByteArray, name: String, issuer: String,
        algo: Int, digits: Int, type: Int, counter: Long,
    ): ByteArray = ByteArrayOutputStream().apply {
        writeBytes(lengthDelim(1, secret))
        writeBytes(lengthDelim(2, name.toByteArray(Charsets.UTF_8)))
        writeBytes(lengthDelim(3, issuer.toByteArray(Charsets.UTF_8)))
        writeBytes(varintField(4, algo.toLong()))
        writeBytes(varintField(5, digits.toLong()))
        writeBytes(varintField(6, type.toLong()))
        if (counter != 0L) writeBytes(varintField(7, counter))
    }.toByteArray()

    private fun migrationUri(batchSize: Int, batchIndex: Int, accounts: List<ByteArray>): String {
        val body = ByteArrayOutputStream().apply {
            for (a in accounts) writeBytes(lengthDelim(1, a))
            writeBytes(varintField(2, 1))                 // version
            writeBytes(varintField(3, batchSize.toLong()))
            writeBytes(varintField(4, batchIndex.toLong()))
        }.toByteArray()
        return wrap(body)
    }

    private fun wrap(body: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(body)
        val encoded = URLEncoder.encode(b64, "UTF-8")
        return "otpauth-migration://offline?data=$encoded"
    }
}
