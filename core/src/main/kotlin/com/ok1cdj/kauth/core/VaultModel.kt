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
 * The plaintext vault contents: an ordered list of accounts. This is what gets
 * JSON-serialized and then encrypted by [VaultCrypto]; it is the same shape used
 * for encrypted backup files, so live vault and backup share one format.
 */
object VaultModel {

    private const val VERSION = 1

    /** Serialize [accounts] to the JSON that will be encrypted. */
    fun serialize(accounts: List<OtpAccount>): String = Json.stringify(
        linkedMapOf<String, Any?>(
            "version" to VERSION,
            "accounts" to accounts.map { acc ->
                linkedMapOf<String, Any?>(
                    "issuer" to acc.issuer,
                    "name" to acc.name,
                    "secret" to acc.secret,
                    "algorithm" to acc.algorithm.name,
                    "digits" to acc.digits,
                    "period" to acc.period,
                    "type" to acc.type.name,
                    "counter" to acc.counter,
                )
            },
        )
    )

    /**
     * Parse the decrypted JSON back to accounts. Malformed entries are skipped
     * rather than failing the whole load, so a single bad record can't lock a user
     * out of the rest of the vault.
     */
    fun deserialize(json: String): List<OtpAccount> {
        val root = runCatching { Json.parseObject(json) }.getOrNull() ?: return emptyList()
        val list = root["accounts"] as? List<*> ?: return emptyList()
        val out = ArrayList<OtpAccount>(list.size)
        for (item in list) {
            val m = item as? Map<*, *> ?: continue
            val secret = m["secret"] as? String ?: continue
            if (!Base32.isValid(secret)) continue
            out.add(
                OtpAccount(
                    issuer = m["issuer"] as? String ?: "",
                    name = m["name"] as? String ?: "",
                    secret = secret.uppercase(),
                    algorithm = OtpAlgorithm.from(m["algorithm"] as? String),
                    digits = (m["digits"] as? Double)?.toInt()?.takeIf { it in 1..9 } ?: 6,
                    period = (m["period"] as? Double)?.toInt()?.takeIf { it > 0 } ?: 30,
                    type = OtpType.from(m["type"] as? String),
                    counter = (m["counter"] as? Double)?.toLong() ?: 0L,
                )
            )
        }
        return out
    }

    /**
     * Merge [incoming] accounts into [current], skipping exact duplicates
     * (same issuer + account + secret). Returns the merged list and how many were
     * added vs. skipped — the default restore/import behaviour.
     */
    fun merge(current: List<OtpAccount>, incoming: List<OtpAccount>): MergeResult {
        val seen = current.mapTo(HashSet()) { it.dedupeKey() }
        val merged = ArrayList(current)
        var added = 0
        var skipped = 0
        for (acc in incoming) {
            if (seen.add(acc.dedupeKey())) {
                merged.add(acc)
                added++
            } else {
                skipped++
            }
        }
        return MergeResult(merged, added, skipped)
    }
}

/** Outcome of a [VaultModel.merge]: the combined list plus counts. */
data class MergeResult(
    val accounts: List<OtpAccount>,
    val added: Int,
    val skipped: Int,
)
