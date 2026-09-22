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

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Decodes Google Authenticator's `otpauth-migration://offline?data=...` export.
 *
 * The payload is a base64 protobuf whose schema is publicly documented (reverse
 * engineered, and used by Aegis/andOTP alike). This is a clean-room decoder built
 * from the field spec — it copies no third-party code:
 *
 * ```
 * MigrationPayload {
 *   repeated OtpParameters otp_parameters = 1;
 *   int32 version   = 2;
 *   int32 batch_size = 3;
 *   int32 batch_index = 4;
 *   int32 batch_id  = 5;
 * }
 * OtpParameters {
 *   bytes  secret    = 1;   // raw secret bytes (NOT Base32)
 *   string name      = 2;
 *   string issuer    = 3;
 *   Algorithm algorithm = 4;  // 1=SHA1 2=SHA256 3=SHA512 4=MD5
 *   DigitCount digits   = 5;  // 1=SIX 2=EIGHT
 *   OtpType type        = 6;  // 1=HOTP 2=TOTP
 *   int64  counter    = 7;
 * }
 * ```
 *
 * Robustness is the whole point of this class (Google Authenticator's own denser
 * multi-account QRs make other importers crash): each account is decoded in
 * isolation, so one malformed entry is recorded as a failure and the rest still
 * import. A completely unreadable payload yields an empty result with one failure
 * — never a thrown exception up to the UI.
 */
object GaMigration {

    private const val SCHEME = "otpauth-migration://"

    /** True if [text] is a Google Authenticator migration URI. */
    fun isMigration(text: String): Boolean =
        text.trim().startsWith(SCHEME, ignoreCase = true)

    /**
     * Decode one migration QR / URI. Never throws for malformed input — failures
     * are collected in [ImportResult.failures].
     */
    fun decode(text: String): ImportResult {
        val data = extractData(text)
            ?: return ImportResult(failures = listOf("missing 'data' parameter"))

        val bytes = runCatching { Base64.getDecoder().decode(data) }
            .recoverCatching { Base64.getUrlDecoder().decode(data) }
            .getOrElse { return ImportResult(failures = listOf("payload is not valid base64")) }

        return parsePayload(bytes)
    }

    private fun extractData(text: String): String? {
        val trimmed = text.trim()
        val q = trimmed.indexOf('?')
        val query = if (q >= 0) trimmed.substring(q + 1) else trimmed
        for (pair in query.split('&')) {
            val eq = pair.indexOf('=')
            if (eq >= 0 && pair.substring(0, eq) == "data") {
                val raw = pair.substring(eq + 1)
                // The base64 is percent-encoded inside the URI; undo that first.
                return runCatching {
                    URLDecoder.decode(raw, StandardCharsets.UTF_8.name())
                }.getOrDefault(raw)
            }
        }
        return null
    }

    private fun parsePayload(bytes: ByteArray): ImportResult {
        val accounts = ArrayList<OtpAccount>()
        val failures = ArrayList<String>()
        var batchIndex = 0
        var batchSize = 1
        var index = 0

        val reader = ProtoReader(bytes)
        try {
            while (reader.hasMore()) {
                val field = reader.readTag()
                when (field) {
                    1 -> { // one OtpParameters
                        index++
                        val chunk = reader.readLengthDelimited()
                        runCatching { parseOtpParameters(chunk) }
                            .onSuccess { accounts.add(it) }
                            .onFailure { failures.add("account #$index: ${it.message ?: "could not be decoded"}") }
                    }
                    3 -> batchSize = reader.readVarint().toInt().coerceAtLeast(1)
                    4 -> batchIndex = reader.readVarint().toInt()
                    else -> reader.skip(reader.lastWireType)
                }
            }
        } catch (e: Exception) {
            // A truncated/corrupt payload still returns whatever decoded before the
            // break, rather than losing the entire batch.
            failures.add("payload truncated after $index account(s): ${e.message ?: "decode error"}")
        }

        return ImportResult(accounts, failures, batchIndex, batchSize)
    }

    private fun parseOtpParameters(bytes: ByteArray): OtpAccount {
        var secret: ByteArray? = null
        var name = ""
        var issuer = ""
        var algorithm = OtpAlgorithm.SHA1
        var digits = 6
        var type = OtpType.TOTP
        var counter = 0L

        val reader = ProtoReader(bytes)
        while (reader.hasMore()) {
            when (reader.readTag()) {
                1 -> secret = reader.readLengthDelimited()
                2 -> name = reader.readString()
                3 -> issuer = reader.readString()
                4 -> algorithm = mapAlgorithm(reader.readVarint().toInt())
                5 -> digits = mapDigits(reader.readVarint().toInt())
                6 -> type = mapType(reader.readVarint().toInt())
                7 -> counter = reader.readVarint()
                else -> reader.skip(reader.lastWireType)
            }
        }

        val secretBytes = secret ?: throw IllegalArgumentException("no secret")
        require(secretBytes.isNotEmpty()) { "empty secret" }

        return OtpAccount(
            issuer = issuer,
            name = name,
            secret = Base32.encode(secretBytes),
            algorithm = algorithm,
            digits = digits,
            period = 30, // GA export carries no period; TOTP is always 30s.
            type = type,
            counter = counter,
        )
    }

    // 0=UNSPECIFIED 1=SHA1 2=SHA256 3=SHA512 4=MD5. MD5 isn't a valid OTP hash for
    // us — reject it so the account is reported rather than silently mis-generating.
    private fun mapAlgorithm(v: Int): OtpAlgorithm = when (v) {
        0, 1 -> OtpAlgorithm.SHA1
        2 -> OtpAlgorithm.SHA256
        3 -> OtpAlgorithm.SHA512
        else -> throw IllegalArgumentException("unsupported algorithm ($v)")
    }

    // 0=UNSPECIFIED 1=SIX 2=EIGHT.
    private fun mapDigits(v: Int): Int = if (v == 2) 8 else 6

    // 0=UNSPECIFIED 1=HOTP 2=TOTP.
    private fun mapType(v: Int): OtpType = if (v == 1) OtpType.HOTP else OtpType.TOTP
}

/**
 * The outcome of decoding one migration part: the accounts that decoded, and a
 * human-readable message for each that did not. [batchIndex]/[batchSize] describe
 * this part's position in a multi-QR export (Google splits exports of >10 accounts).
 */
data class ImportResult(
    val accounts: List<OtpAccount> = emptyList(),
    val failures: List<String> = emptyList(),
    val batchIndex: Int = 0,
    val batchSize: Int = 1,
)
