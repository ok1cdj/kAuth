/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 */

package com.ok1cdj.kauth.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class VaultModelTest {

    private fun acc(issuer: String, name: String, secret: String = "JBSWY3DPEHPK3PXP") =
        OtpAccount(issuer = issuer, name = name, secret = secret)

    @Test
    fun `serialize then deserialize round-trips all fields`() {
        val accounts = listOf(
            OtpAccount("ACME", "alice", "JBSWY3DPEHPK3PXP", OtpAlgorithm.SHA256, 8, 60, OtpType.TOTP, 0),
            OtpAccount("Globex", "bob", "MZXW6YTBOI", OtpAlgorithm.SHA512, 6, 30, OtpType.HOTP, 12),
        )
        val restored = VaultModel.deserialize(VaultModel.serialize(accounts))
        assertEquals(accounts, restored)
    }

    @Test
    fun `deserialize skips malformed records`() {
        val json = """{"version":1,"accounts":[
            {"issuer":"A","name":"ok","secret":"JBSWY3DPEHPK3PXP"},
            {"issuer":"B","name":"no-secret"},
            {"issuer":"C","name":"bad-secret","secret":"!!!!"}
        ]}""".trimIndent()
        val accounts = VaultModel.deserialize(json)
        assertEquals(1, accounts.size)
        assertEquals("ok", accounts[0].name)
    }

    @Test
    fun `merge adds new accounts and skips exact duplicates`() {
        val current = listOf(acc("ACME", "alice"), acc("Globex", "bob"))
        val incoming = listOf(
            acc("ACME", "alice"),                        // exact dup
            acc("ACME", "alice", "MZXW6YTBOI"),          // same label, different secret -> new
            acc("Initech", "carol"),                     // new
        )
        val result = VaultModel.merge(current, incoming)
        assertEquals(4, result.accounts.size)
        assertEquals(2, result.added)
        assertEquals(1, result.skipped)
    }

    @Test
    fun `empty json yields no accounts`() {
        assertEquals(0, VaultModel.deserialize("").size)
        assertEquals(0, VaultModel.deserialize("{}").size)
    }
}
