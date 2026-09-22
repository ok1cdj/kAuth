/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 */

package com.ok1cdj.kauth.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultCryptoTest {

    // Light KDF parameters keep the unit tests fast; production uses the defaults.
    private val fast = VaultCrypto.KdfParams(memoryKib = 1024, iterations = 1, parallelism = 1)

    @Test
    fun `encrypt then decrypt round-trips`() {
        val plaintext = "the vault contents — ěščř 🔐".toByteArray(Charsets.UTF_8)
        val blob = VaultCrypto.encrypt(plaintext, "correct horse".toCharArray(), fast)
        val out = VaultCrypto.decrypt(blob, "correct horse".toCharArray())
        assertArrayEquals(plaintext, out)
    }

    @Test
    fun `wrong password throws WrongPasswordException`() {
        val blob = VaultCrypto.encrypt("data".toByteArray(), "right".toCharArray(), fast)
        assertThrows(WrongPasswordException::class.java) {
            VaultCrypto.decrypt(blob, "wrong".toCharArray())
        }
    }

    @Test
    fun `ciphertext differs each time for the same input`() {
        val pw = "same-password".toCharArray()
        val a = VaultCrypto.encrypt("data".toByteArray(), pw.copyOf(), fast)
        val b = VaultCrypto.encrypt("data".toByteArray(), pw.copyOf(), fast)
        assertNotEquals(a, b) // random salt + VMK + nonces
    }

    @Test
    fun `changePassword rewraps and old password stops working`() {
        val plaintext = "secret".toByteArray()
        val blob = VaultCrypto.encrypt(plaintext, "old-password".toCharArray(), fast)
        val rewrapped = VaultCrypto.changePassword(blob, "old-password".toCharArray(), "new-password".toCharArray(), fast)

        assertArrayEquals(plaintext, VaultCrypto.decrypt(rewrapped, "new-password".toCharArray()))
        assertThrows(WrongPasswordException::class.java) {
            VaultCrypto.decrypt(rewrapped, "old-password".toCharArray())
        }
    }

    @Test
    fun `changePassword with wrong old password throws`() {
        val blob = VaultCrypto.encrypt("x".toByteArray(), "old".toCharArray(), fast)
        assertThrows(WrongPasswordException::class.java) {
            VaultCrypto.changePassword(blob, "bad".toCharArray(), "new".toCharArray(), fast)
        }
    }

    @Test
    fun `malformed blob throws VaultFormatException`() {
        assertThrows(VaultFormatException::class.java) {
            VaultCrypto.decrypt("not a vault", "pw".toCharArray())
        }
    }

    @Test
    fun `header stores kdf params for portability`() {
        val blob = VaultCrypto.encrypt("x".toByteArray(), "pw".toCharArray(), fast)
        assertTrue(blob.contains("\"kdf\":\"argon2id\""))
        assertTrue(blob.contains("\"mem\":1024"))
    }

    // --- session-key API -----------------------------------------------------

    @Test
    fun `create returns a VMK that opens the data`() {
        val plaintext = "session data".toByteArray()
        val sealed = VaultCrypto.create(plaintext, "pw".toCharArray(), fast)
        // The returned VMK decrypts the data directly...
        assertArrayEquals(plaintext, VaultCrypto.decryptData(sealed.blob, sealed.vmk))
        // ...and the password still opens it the classic way.
        assertArrayEquals(plaintext, VaultCrypto.decrypt(sealed.blob, "pw".toCharArray()))
    }

    @Test
    fun `unlock returns the same VMK the data was sealed with`() {
        val plaintext = "abc".toByteArray()
        val sealed = VaultCrypto.create(plaintext, "pw".toCharArray(), fast)
        val vmk = VaultCrypto.unlock(sealed.blob, "pw".toCharArray())
        assertArrayEquals(sealed.vmk, vmk)
        assertArrayEquals(plaintext, VaultCrypto.decryptData(sealed.blob, vmk))
    }

    @Test
    fun `unlock throws on wrong password`() {
        val sealed = VaultCrypto.create("x".toByteArray(), "right".toCharArray(), fast)
        assertThrows(WrongPasswordException::class.java) {
            VaultCrypto.unlock(sealed.blob, "wrong".toCharArray())
        }
    }

    @Test
    fun `resealData keeps the same password and updates the plaintext`() {
        val sealed = VaultCrypto.create("v1".toByteArray(), "pw".toCharArray(), fast)
        val updated = VaultCrypto.resealData(sealed.blob, sealed.vmk, "v2".toByteArray())
        // Same password still opens the resealed blob and yields the new data.
        assertArrayEquals("v2".toByteArray(), VaultCrypto.decrypt(updated, "pw".toCharArray()))
        // Same VMK also opens it (header/wrapped-VMK untouched).
        assertArrayEquals("v2".toByteArray(), VaultCrypto.decryptData(updated, sealed.vmk))
    }

    @Test
    fun `rewrap changes the password but keeps the VMK and data`() {
        val sealed = VaultCrypto.create("data".toByteArray(), "old".toCharArray(), fast)
        val rewrapped = VaultCrypto.rewrap(sealed.blob, sealed.vmk, "new".toCharArray(), fast)
        // New password opens it, old does not; the same VMK still works.
        assertArrayEquals("data".toByteArray(), VaultCrypto.decrypt(rewrapped, "new".toCharArray()))
        assertArrayEquals("data".toByteArray(), VaultCrypto.decryptData(rewrapped, sealed.vmk))
        assertThrows(WrongPasswordException::class.java) {
            VaultCrypto.unlock(rewrapped, "old".toCharArray())
        }
    }
}
