/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 */

package com.ok1cdj.kauth.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OtpUriTest {

    @Test
    fun `parses a full totp URI`() {
        val uri = "otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP" +
            "&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60"
        val acc = OtpUri.parse(uri)
        assertEquals("ACME Co", acc.issuer)
        assertEquals("john@example.com", acc.name)
        assertEquals("JBSWY3DPEHPK3PXP", acc.secret)
        assertEquals(OtpAlgorithm.SHA256, acc.algorithm)
        assertEquals(8, acc.digits)
        assertEquals(60, acc.period)
        assertEquals(OtpType.TOTP, acc.type)
    }

    @Test
    fun `issuer parameter overrides the label prefix`() {
        val acc = OtpUri.parse("otpauth://totp/Old:alice?secret=JBSWY3DPEHPK3PXP&issuer=New")
        assertEquals("New", acc.issuer)
        assertEquals("alice", acc.name)
    }

    @Test
    fun `applies defaults when optionals are absent`() {
        val acc = OtpUri.parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
        assertEquals("", acc.issuer)
        assertEquals("alice", acc.name)
        assertEquals(OtpAlgorithm.SHA1, acc.algorithm)
        assertEquals(6, acc.digits)
        assertEquals(30, acc.period)
    }

    @Test
    fun `parses hotp with counter`() {
        val acc = OtpUri.parse("otpauth://hotp/acc?secret=JBSWY3DPEHPK3PXP&counter=42")
        assertEquals(OtpType.HOTP, acc.type)
        assertEquals(42L, acc.counter)
    }

    @Test
    fun `ignores unknown query parameters`() {
        val acc = OtpUri.parse("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&color=blue&foo=bar")
        assertEquals("JBSWY3DPEHPK3PXP", acc.secret)
    }

    @Test
    fun `missing or bad secret throws`() {
        assertThrows(IllegalArgumentException::class.java) { OtpUri.parse("otpauth://totp/a?issuer=x") }
        assertThrows(IllegalArgumentException::class.java) { OtpUri.parse("otpauth://totp/a?secret=not!base32") }
    }

    @Test
    fun `wrong scheme or type throws`() {
        assertThrows(IllegalArgumentException::class.java) { OtpUri.parse("https://example.com") }
        assertThrows(IllegalArgumentException::class.java) { OtpUri.parse("otpauth://mtp/a?secret=JBSWY3DPEHPK3PXP") }
    }

    @Test
    fun `build then parse round-trips`() {
        val original = OtpAccount(
            issuer = "ACME Co",
            name = "john@example.com",
            secret = "JBSWY3DPEHPK3PXP",
            algorithm = OtpAlgorithm.SHA512,
            digits = 8,
            period = 45,
            type = OtpType.TOTP,
        )
        val round = OtpUri.parse(OtpUri.build(original))
        assertEquals(original, round)
    }

    @Test
    fun `isOtpAuth detects the scheme`() {
        assertTrue(OtpUri.isOtpAuth("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"))
        assertTrue(OtpUri.isOtpAuth("  OTPAUTH://totp/a?secret=x"))
    }
}
