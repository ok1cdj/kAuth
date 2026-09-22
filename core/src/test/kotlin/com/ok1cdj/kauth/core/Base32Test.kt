/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 */

package com.ok1cdj.kauth.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class Base32Test {

    // RFC 4648 §10 test vectors.
    private val vectors = listOf(
        "" to "",
        "f" to "MY",
        "fo" to "MZXQ",
        "foo" to "MZXW6",
        "foob" to "MZXW6YQ",
        "fooba" to "MZXW6YTB",
        "foobar" to "MZXW6YTBOI",
    )

    @Test
    fun `encode matches RFC 4648 vectors`() {
        for ((plain, encoded) in vectors) {
            assertEquals(encoded, Base32.encode(plain.toByteArray(Charsets.US_ASCII)), "encode '$plain'")
        }
    }

    @Test
    fun `decode matches RFC 4648 vectors`() {
        for ((plain, encoded) in vectors) {
            assertArrayEquals(plain.toByteArray(Charsets.US_ASCII), Base32.decode(encoded), "decode '$encoded'")
        }
    }

    @Test
    fun `decode is lenient about case, spaces and padding`() {
        val expected = "foobar".toByteArray(Charsets.US_ASCII)
        assertArrayEquals(expected, Base32.decode("mzxw6ytboi"))
        assertArrayEquals(expected, Base32.decode("MZXW 6YTB OI"))
        assertArrayEquals(expected, Base32.decode("MZXW6YTBOI======"))
    }

    @Test
    fun `round-trips arbitrary bytes`() {
        val data = ByteArray(37) { (it * 7 - 3).toByte() }
        assertArrayEquals(data, Base32.decode(Base32.encode(data)))
    }

    @Test
    fun `invalid characters throw`() {
        assertThrows(IllegalArgumentException::class.java) { Base32.decode("MZXW6YTB01") } // 0 and 1 not in alphabet
    }

    @Test
    fun `isValid reflects decodability`() {
        assertTrue(Base32.isValid("JBSWY3DPEHPK3PXP"))
        assertFalse(Base32.isValid("not base32!"))
        assertFalse(Base32.isValid(""))
    }
}
