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
 * Master-password policy and a coarse strength estimate for the UI meter.
 *
 * The policy is deliberately light-touch, matching the spec: block only the
 * genuinely trivial (too short, empty, obvious sequences and well-known
 * passwords), and otherwise leave the choice to the user. There is no maximum and
 * no character-class requirement — a long passphrase should always be allowed.
 */
object PasswordStrength {

    /** Minimum length. Below this the password is rejected outright. */
    const val MIN_LENGTH = 8

    /** Coarse buckets for the strength meter. */
    enum class Level { TOO_SHORT, WEAK, FAIR, GOOD, STRONG }

    private val TRIVIAL = setOf(
        "password", "passw0rd", "12345678", "123456789", "1234567890",
        "qwertyui", "qwerty123", "11111111", "00000000", "letmein",
        "iloveyou", "admin123", "welcome1", "abc12345",
    )

    /**
     * @return the strength [Level]. [Level.TOO_SHORT] and a trivial match both
     *   count as unacceptable (see [isAcceptable]).
     */
    fun evaluate(password: String): Level {
        if (password.length < MIN_LENGTH) return Level.TOO_SHORT
        if (isTrivial(password)) return Level.WEAK

        var classes = 0
        if (password.any { it.isLowerCase() }) classes++
        if (password.any { it.isUpperCase() }) classes++
        if (password.any { it.isDigit() }) classes++
        if (password.any { !it.isLetterOrDigit() }) classes++

        val len = password.length
        // Score blends length and variety; long passphrases reach STRONG on length
        // alone, short-but-varied passwords reach GOOD.
        return when {
            len >= 16 || (len >= 12 && classes >= 3) -> Level.STRONG
            len >= 12 || (len >= 10 && classes >= 2) -> Level.GOOD
            classes >= 2 -> Level.FAIR
            else -> Level.WEAK
        }
    }

    /**
     * Whether a password may be used. Only the trivial cases are blocked:
     * shorter than [MIN_LENGTH], a known-common password, or a single repeated
     * character / simple sequence. Everything else is the user's call.
     */
    fun isAcceptable(password: String): Boolean =
        password.length >= MIN_LENGTH && !isTrivial(password)

    private fun isTrivial(password: String): Boolean {
        val lower = password.lowercase()
        if (lower in TRIVIAL) return true
        if (password.isNotEmpty() && password.all { it == password[0] }) return true // aaaaaaaa
        if (isSequential(password)) return true // 12345678 / abcdefgh
        return false
    }

    private fun isSequential(password: String): Boolean {
        if (password.length < MIN_LENGTH) return false
        var ascending = true
        var descending = true
        for (i in 1 until password.length) {
            val diff = password[i].code - password[i - 1].code
            if (diff != 1) ascending = false
            if (diff != -1) descending = false
        }
        return ascending || descending
    }
}
