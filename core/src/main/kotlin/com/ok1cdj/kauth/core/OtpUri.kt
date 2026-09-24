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
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Parse and build `otpauth://` URIs (Key Uri Format).
 *
 * Format: `otpauth://{totp|hotp}/{label}?secret=...&issuer=...&algorithm=...&digits=...&period=...&counter=...`
 *
 * The label is `issuer:account` or just `account`. An `issuer` query parameter,
 * when present, wins over the label prefix. Parsing is lenient: unknown query
 * parameters are ignored and missing optionals fall back to the standard
 * defaults, so codes still work when an issuer over-specifies the URI.
 */
object OtpUri {

    private const val SCHEME = "otpauth://"

    /** True if [text] looks like a single `otpauth://` account URI. */
    fun isOtpAuth(text: String): Boolean =
        text.trim().startsWith(SCHEME, ignoreCase = true)

    /**
     * Parse a single `otpauth://` URI into an [OtpAccount].
     *
     * @throws IllegalArgumentException if the scheme/type is wrong or the required
     *   `secret` parameter is missing or not valid Base32.
     */
    fun parse(text: String): OtpAccount {
        val uri = text.trim()
        require(uri.startsWith(SCHEME, ignoreCase = true)) { "not an otpauth:// URI" }
        val rest = uri.substring(SCHEME.length)

        val queryStart = rest.indexOf('?')
        val path = if (queryStart >= 0) rest.substring(0, queryStart) else rest
        val query = if (queryStart >= 0) rest.substring(queryStart + 1) else ""

        val slash = path.indexOf('/')
        val typeStr = if (slash >= 0) path.substring(0, slash) else path
        val type = when (typeStr.lowercase()) {
            "totp" -> OtpType.TOTP
            "hotp" -> OtpType.HOTP
            else -> throw IllegalArgumentException("unknown otpauth type: '$typeStr'")
        }

        val rawLabel = if (slash >= 0) path.substring(slash + 1) else ""
        val params = parseQuery(query)

        val secret = params["secret"]?.replace(" ", "")
            ?: throw IllegalArgumentException("otpauth URI has no secret")
        require(Base32.isValid(secret)) { "otpauth secret is not valid Base32" }

        // Label is "issuer:account"; the issuer= parameter overrides the prefix.
        // Split on a literal ':' before decoding, so an issuer containing an
        // encoded colon (as [build] writes it) stays intact; only when there is no
        // literal separator fall back to an encoded one ("%3A").
        val labelIssuer: String
        val account: String
        val rawColon = rawLabel.indexOf(':')
        val label = decode(rawLabel)
        val colon = label.indexOf(':')
        if (rawColon >= 0) {
            labelIssuer = decode(rawLabel.substring(0, rawColon)).trim()
            account = decode(rawLabel.substring(rawColon + 1)).trim()
        } else if (colon >= 0) {
            labelIssuer = label.substring(0, colon).trim()
            account = label.substring(colon + 1).trim()
        } else {
            labelIssuer = ""
            account = label.trim()
        }
        val issuer = (params["issuer"]?.trim().takeUnless { it.isNullOrEmpty() }) ?: labelIssuer

        val digits = params["digits"]?.toIntOrNull()?.takeIf { it in 1..9 } ?: 6
        val period = params["period"]?.toIntOrNull()?.takeIf { it > 0 } ?: 30
        val counter = params["counter"]?.toLongOrNull() ?: 0L

        return OtpAccount(
            issuer = issuer,
            name = account,
            secret = secret.uppercase(),
            algorithm = OtpAlgorithm.from(params["algorithm"]),
            digits = digits,
            period = period,
            type = type,
            counter = counter,
        )
    }

    /** Build a canonical `otpauth://` URI for [account]. */
    fun build(account: OtpAccount): String {
        val type = if (account.type == OtpType.HOTP) "hotp" else "totp"
        val label = if (account.issuer.isNotBlank()) {
            "${encode(account.issuer)}:${encode(account.name)}"
        } else {
            encode(account.name)
        }
        val params = buildList {
            add("secret=${account.secret}")
            if (account.issuer.isNotBlank()) add("issuer=${encode(account.issuer)}")
            add("algorithm=${account.algorithm.name}")
            add("digits=${account.digits}")
            if (account.type == OtpType.TOTP) add("period=${account.period}")
            if (account.type == OtpType.HOTP) add("counter=${account.counter}")
        }
        return "$SCHEME$type/$label?${params.joinToString("&")}"
    }

    /** [build] for every account, one URI per line (with a trailing newline). */
    fun buildAll(accounts: List<OtpAccount>): String =
        accounts.joinToString(separator = "\n", postfix = if (accounts.isEmpty()) "" else "\n") { build(it) }

    private fun parseQuery(query: String): Map<String, String> {
        if (query.isBlank()) return emptyMap()
        val map = LinkedHashMap<String, String>()
        for (pair in query.split('&')) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            if (eq < 0) {
                map[decode(pair)] = ""
            } else {
                map[decode(pair.substring(0, eq))] = decode(pair.substring(eq + 1))
            }
        }
        return map
    }

    private fun decode(s: String): String =
        runCatching { URLDecoder.decode(s, StandardCharsets.UTF_8.name()) }.getOrDefault(s)

    private fun encode(s: String): String =
        URLEncoder.encode(s, StandardCharsets.UTF_8.name()).replace("+", "%20")
}
