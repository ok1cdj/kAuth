/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 */

package com.ok1cdj.kauth.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class OtpTest {

    // RFC 4226 Appendix D — secret "12345678901234567890", SHA1, 6 digits.
    private val hotpKey = "12345678901234567890".toByteArray(Charsets.US_ASCII)

    @Test
    fun `RFC 4226 HOTP vectors`() {
        val expected = listOf(
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        )
        for (c in expected.indices) {
            assertEquals(expected[c], Otp.hotp(hotpKey, c.toLong(), 6, OtpAlgorithm.SHA1), "counter $c")
        }
    }

    // RFC 6238 Appendix B — per-algorithm seeds, 8 digits.
    private val sha1Key = "12345678901234567890".toByteArray(Charsets.US_ASCII)
    private val sha256Key = "12345678901234567890123456789012".toByteArray(Charsets.US_ASCII)
    private val sha512Key =
        "1234567890123456789012345678901234567890123456789012345678901234".toByteArray(Charsets.US_ASCII)

    @Test
    fun `RFC 6238 TOTP SHA1 vectors`() {
        val cases = mapOf(
            59L to "94287082",
            1111111109L to "07081804",
            1111111111L to "14050471",
            1234567890L to "89005924",
            2000000000L to "69279037",
            20000000000L to "65353130",
        )
        for ((secs, expected) in cases) {
            assertEquals(expected, Otp.totp(sha1Key, secs * 1000, 30, 8, OtpAlgorithm.SHA1), "t=$secs")
        }
    }

    @Test
    fun `RFC 6238 TOTP SHA256 vectors`() {
        val cases = mapOf(
            59L to "46119246",
            1111111109L to "68084774",
            1111111111L to "67062674",
            1234567890L to "91819424",
            2000000000L to "90698825",
            20000000000L to "77737706",
        )
        for ((secs, expected) in cases) {
            assertEquals(expected, Otp.totp(sha256Key, secs * 1000, 30, 8, OtpAlgorithm.SHA256), "t=$secs")
        }
    }

    @Test
    fun `RFC 6238 TOTP SHA512 vectors`() {
        val cases = mapOf(
            59L to "90693936",
            1111111109L to "25091201",
            1111111111L to "99943326",
            1234567890L to "93441116",
            2000000000L to "38618901",
            20000000000L to "47863826",
        )
        for ((secs, expected) in cases) {
            assertEquals(expected, Otp.totp(sha512Key, secs * 1000, 30, 8, OtpAlgorithm.SHA512), "t=$secs")
        }
    }

    @Test
    fun `secondsRemaining counts down within the period`() {
        assertEquals(30, Otp.secondsRemaining(30, 0L))
        assertEquals(29, Otp.secondsRemaining(30, 1_000L))
        assertEquals(1, Otp.secondsRemaining(30, 29_000L))
        assertEquals(30, Otp.secondsRemaining(30, 30_000L))
    }

    @Test
    fun `code() decodes Base32 and matches the RFC SHA1 vector`() {
        // Base32 of the RFC seed "12345678901234567890".
        val secret = Base32.encode(sha1Key)
        val acc = OtpAccount(issuer = "ACME", name = "alice", secret = secret, digits = 8)
        assertEquals("94287082", Otp.code(acc, 59_000L))
    }
}
