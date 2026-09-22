/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 */

package com.ok1cdj.kauth.core

import com.ok1cdj.kauth.core.PasswordStrength.Level
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PasswordStrengthTest {

    @Test
    fun `blocks trivial and short passwords`() {
        assertFalse(PasswordStrength.isAcceptable(""))
        assertFalse(PasswordStrength.isAcceptable("1234"))
        assertFalse(PasswordStrength.isAcceptable("short"))
        assertFalse(PasswordStrength.isAcceptable("password"))
        assertFalse(PasswordStrength.isAcceptable("12345678"))   // sequence
        assertFalse(PasswordStrength.isAcceptable("aaaaaaaa"))   // repeated
        assertFalse(PasswordStrength.isAcceptable("abcdefgh"))   // sequence
    }

    @Test
    fun `accepts anything non-trivial at or above the minimum length`() {
        assertTrue(PasswordStrength.isAcceptable("tractor9"))       // 8 chars, mixed
        assertTrue(PasswordStrength.isAcceptable("correct horse battery staple"))
    }

    @Test
    fun `evaluate buckets by length and variety`() {
        assertEquals(Level.TOO_SHORT, PasswordStrength.evaluate("abc"))
        assertEquals(Level.WEAK, PasswordStrength.evaluate("password"))
        assertEquals(Level.STRONG, PasswordStrength.evaluate("correct horse battery staple"))
        assertEquals(Level.STRONG, PasswordStrength.evaluate("Xk9\$mQ2!Lp7@Zr4"))
    }

    @Test
    fun `min length constant is enforced consistently`() {
        assertEquals(Level.TOO_SHORT, PasswordStrength.evaluate("a1"))
        assertFalse(PasswordStrength.isAcceptable("a1"))
    }
}
