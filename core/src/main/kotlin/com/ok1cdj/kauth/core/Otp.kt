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

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HOTP (RFC 4226) and TOTP (RFC 6238) code generation, built only on the standard
 * `javax.crypto` HMAC — no third-party crypto. All functions take the raw key
 * bytes; Base32 decoding is the caller's job (see [Base32]).
 */
object Otp {

    private val POW10 = intArrayOf(
        1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000,
    )

    /**
     * RFC 4226 HOTP: HMAC of the 8-byte big-endian [counter], dynamically
     * truncated to [digits] decimal digits, zero-padded.
     */
    fun hotp(
        key: ByteArray,
        counter: Long,
        digits: Int = 6,
        algorithm: OtpAlgorithm = OtpAlgorithm.SHA1,
    ): String {
        require(digits in 1..9) { "digits must be 1..9, was $digits" }
        val msg = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            msg[i] = (c and 0xFF).toByte()
            c = c ushr 8
        }
        val hash = hmac(key, msg, algorithm)
        // Dynamic truncation (RFC 4226 §5.3).
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        val otp = binary % POW10[digits]
        return otp.toString().padStart(digits, '0')
    }

    /**
     * RFC 6238 TOTP for the given [timeMillis] (defaults to now) and [period]
     * seconds. Equivalent to HOTP with counter = floor(unixSeconds / period).
     */
    fun totp(
        key: ByteArray,
        timeMillis: Long = System.currentTimeMillis(),
        period: Int = 30,
        digits: Int = 6,
        algorithm: OtpAlgorithm = OtpAlgorithm.SHA1,
    ): String {
        require(period > 0) { "period must be > 0, was $period" }
        val counter = Math.floorDiv(timeMillis / 1000, period.toLong())
        return hotp(key, counter, digits, algorithm)
    }

    /** Seconds remaining in the current TOTP step for [timeMillis] and [period]. */
    fun secondsRemaining(
        period: Int = 30,
        timeMillis: Long = System.currentTimeMillis(),
    ): Int {
        val secs = timeMillis / 1000
        return (period - Math.floorMod(secs, period.toLong())).toInt()
    }

    /**
     * Generate the current code for [account]. Decodes the Base32 secret and,
     * for TOTP, uses [timeMillis]; for HOTP, uses the account's stored counter.
     */
    fun code(account: OtpAccount, timeMillis: Long = System.currentTimeMillis()): String {
        val key = Base32.decode(account.secret)
        return when (account.type) {
            OtpType.TOTP -> totp(key, timeMillis, account.period, account.digits, account.algorithm)
            OtpType.HOTP -> hotp(key, account.counter, account.digits, account.algorithm)
        }
    }

    private fun hmac(key: ByteArray, message: ByteArray, algorithm: OtpAlgorithm): ByteArray {
        val mac = Mac.getInstance(algorithm.macName)
        mac.init(SecretKeySpec(key, algorithm.macName))
        return mac.doFinal(message)
    }
}
