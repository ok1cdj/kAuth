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

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Thrown when a vault cannot be decrypted with the supplied password. */
class WrongPasswordException : Exception("wrong master password")

/** Thrown when a vault blob is not in a recognisable/complete format. */
class VaultFormatException(message: String) : Exception(message)

/**
 * The result of sealing a fresh vault: the serialized [blob] and the raw
 * **vault master key** ([vmk]) that opens it. The caller keeps the VMK in memory
 * for the session (cheap re-saves via [VaultCrypto.resealData], and to offer the
 * key to a biometric wrap) and must zero it on lock.
 */
class SealResult(val blob: String, val vmk: ByteArray)

/**
 * Envelope encryption for the vault, using **only** javax.crypto (AES-256-GCM)
 * plus BouncyCastle for the Argon2id KDF.
 *
 * The design deliberately separates the data key from the password so a future
 * biometric unlock (v2) can be added without re-encrypting or migrating the vault:
 *
 *  1. A random 256-bit **vault master key (VMK)** encrypts the plaintext (the
 *     account JSON) with AES-256-GCM.
 *  2. A **key-encryption key (KEK)** is derived from the master password with
 *     Argon2id (random per-vault salt, parameters stored in the header) and wraps
 *     the VMK with AES-256-GCM.
 *
 * To decrypt: derive the KEK, unwrap the VMK, decrypt the data. A wrong password
 * fails GCM authentication when unwrapping the VMK — surfaced as
 * [WrongPasswordException]. In v2, a second wrap of the *same* VMK by a Keystore
 * biometric-bound key can be added as another header field; the data ciphertext
 * never changes.
 *
 * The serialized blob is a small JSON header carrying base64 fields — safe to keep
 * in DataStore or write to a backup file.
 */
object VaultCrypto {

    const val FORMAT_VERSION = 1
    private const val KEY_BYTES = 32   // AES-256
    private const val SALT_BYTES = 16
    private const val NONCE_BYTES = 12 // GCM standard
    private const val TAG_BITS = 128

    private val rng = SecureRandom()

    /**
     * Argon2id cost parameters. The default (32 MiB, 3 iterations, 1 lane) is a
     * deliberate compromise for the low-power Kompakt CPU — memory-hard and well
     * above OWASP's Argon2id minimums, while keeping unlock responsive (~1–2 s on
     * the device rather than several). The chosen params are stored per-vault in
     * the header, so existing vaults keep whatever they were created with.
     */
    data class KdfParams(
        val memoryKib: Int = 32_768,
        val iterations: Int = 3,
        val parallelism: Int = 1,
    )

    /** Encrypt [plaintext] under [password], generating a fresh VMK and salt. */
    fun encrypt(plaintext: ByteArray, password: CharArray, params: KdfParams = KdfParams()): String {
        val salt = randomBytes(SALT_BYTES)
        val vmk = randomBytes(KEY_BYTES)
        val kek = deriveKek(password, salt, params)
        try {
            val wrapNonce = randomBytes(NONCE_BYTES)
            val wrapped = gcmEncrypt(kek, wrapNonce, vmk)
            val dataNonce = randomBytes(NONCE_BYTES)
            val data = gcmEncrypt(vmk, dataNonce, plaintext)
            return serialize(salt, params, wrapNonce, wrapped, dataNonce, data)
        } finally {
            kek.fill(0)
            vmk.fill(0)
        }
    }

    /** Decrypt a vault blob, returning the plaintext. */
    fun decrypt(blob: String, password: CharArray): ByteArray {
        val h = parse(blob)
        val kek = deriveKek(password, h.salt, h.params)
        val vmk: ByteArray
        try {
            vmk = try {
                gcmDecrypt(kek, h.wrapNonce, h.wrapped)
            } catch (e: AEADBadTagException) {
                throw WrongPasswordException()
            }
        } finally {
            kek.fill(0)
        }
        try {
            return gcmDecrypt(vmk, h.dataNonce, h.data)
        } catch (e: AEADBadTagException) {
            // VMK unwrapped but data failed — corrupt vault, not a wrong password.
            throw VaultFormatException("vault data failed authentication")
        } finally {
            vmk.fill(0)
        }
    }

    /**
     * Re-wrap the VMK under a new password without touching the data ciphertext.
     * A fresh salt and Argon2 parameters are used. The [oldPassword] must be
     * correct or [WrongPasswordException] is thrown.
     */
    fun changePassword(
        blob: String,
        oldPassword: CharArray,
        newPassword: CharArray,
        params: KdfParams = KdfParams(),
    ): String {
        val h = parse(blob)
        val oldKek = deriveKek(oldPassword, h.salt, h.params)
        val vmk = try {
            try {
                gcmDecrypt(oldKek, h.wrapNonce, h.wrapped)
            } catch (e: AEADBadTagException) {
                throw WrongPasswordException()
            }
        } finally {
            oldKek.fill(0)
        }
        try {
            val newSalt = randomBytes(SALT_BYTES)
            val newKek = deriveKek(newPassword, newSalt, params)
            try {
                val newWrapNonce = randomBytes(NONCE_BYTES)
                val newWrapped = gcmEncrypt(newKek, newWrapNonce, vmk)
                return serialize(newSalt, params, newWrapNonce, newWrapped, h.dataNonce, h.data)
            } finally {
                newKek.fill(0)
            }
        } finally {
            vmk.fill(0)
        }
    }

    // --- session-key API (VMK held in memory while unlocked) -----------------

    /**
     * Seal [plaintext] under [password] with a fresh VMK, returning both the blob
     * and the VMK so the caller can start a session without a second KDF pass.
     */
    fun create(plaintext: ByteArray, password: CharArray, params: KdfParams = KdfParams()): SealResult {
        val salt = randomBytes(SALT_BYTES)
        val vmk = randomBytes(KEY_BYTES)
        val kek = deriveKek(password, salt, params)
        try {
            val wrapNonce = randomBytes(NONCE_BYTES)
            val wrapped = gcmEncrypt(kek, wrapNonce, vmk)
            val dataNonce = randomBytes(NONCE_BYTES)
            val data = gcmEncrypt(vmk, dataNonce, plaintext)
            return SealResult(serialize(salt, params, wrapNonce, wrapped, dataNonce, data), vmk.copyOf())
        } finally {
            kek.fill(0)
            vmk.fill(0)
        }
    }

    /**
     * Derive the KEK from [password] and return the unwrapped **VMK** (the session
     * key). Throws [WrongPasswordException] if the password does not open the vault.
     */
    fun unlock(blob: String, password: CharArray): ByteArray {
        val h = parse(blob)
        val kek = deriveKek(password, h.salt, h.params)
        try {
            return try {
                gcmDecrypt(kek, h.wrapNonce, h.wrapped)
            } catch (e: AEADBadTagException) {
                throw WrongPasswordException()
            }
        } finally {
            kek.fill(0)
        }
    }

    /** Decrypt the data section of [blob] with an already-unwrapped [vmk]. */
    fun decryptData(blob: String, vmk: ByteArray): ByteArray {
        val h = parse(blob)
        return try {
            gcmDecrypt(vmk, h.dataNonce, h.data)
        } catch (e: AEADBadTagException) {
            throw VaultFormatException("vault data failed authentication")
        }
    }

    /**
     * Re-encrypt the data section with the in-memory [vmk], keeping the header
     * (salt, KDF params, password-wrapped VMK) untouched. The cheap save path —
     * **no Argon2** — used on every account change during a session.
     */
    fun resealData(blob: String, vmk: ByteArray, newPlaintext: ByteArray): String {
        val h = parse(blob)
        val dataNonce = randomBytes(NONCE_BYTES)
        val data = gcmEncrypt(vmk, dataNonce, newPlaintext)
        return serialize(h.salt, h.params, h.wrapNonce, h.wrapped, dataNonce, data)
    }

    /**
     * Wrap the already-unwrapped [vmk] under a [newPassword] (fresh salt + KEK),
     * leaving the data ciphertext untouched. Used to change the master password
     * from an unlocked session without re-deriving the old KEK.
     */
    fun rewrap(blob: String, vmk: ByteArray, newPassword: CharArray, params: KdfParams = KdfParams()): String {
        val h = parse(blob)
        val newSalt = randomBytes(SALT_BYTES)
        val newKek = deriveKek(newPassword, newSalt, params)
        try {
            val newWrapNonce = randomBytes(NONCE_BYTES)
            val newWrapped = gcmEncrypt(newKek, newWrapNonce, vmk)
            return serialize(newSalt, params, newWrapNonce, newWrapped, h.dataNonce, h.data)
        } finally {
            newKek.fill(0)
        }
    }

    // --- KDF -----------------------------------------------------------------

    private fun deriveKek(password: CharArray, salt: ByteArray, params: KdfParams): ByteArray {
        val passwordBytes = charsToUtf8(password)
        try {
            val gen = Argon2BytesGenerator()
            gen.init(
                Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(params.iterations)
                    .withMemoryAsKB(params.memoryKib)
                    .withParallelism(params.parallelism)
                    .withSalt(salt)
                    .build()
            )
            val out = ByteArray(KEY_BYTES)
            gen.generateBytes(passwordBytes, out)
            return out
        } finally {
            passwordBytes.fill(0)
        }
    }

    // --- AES-256-GCM ---------------------------------------------------------

    private fun gcmEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        return cipher.doFinal(plaintext)
    }

    private fun gcmDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        return cipher.doFinal(ciphertext)
    }

    // --- serialization -------------------------------------------------------

    private fun serialize(
        salt: ByteArray,
        params: KdfParams,
        wrapNonce: ByteArray,
        wrapped: ByteArray,
        dataNonce: ByteArray,
        data: ByteArray,
    ): String = Json.stringify(
        linkedMapOf<String, Any?>(
            "v" to FORMAT_VERSION,
            "kdf" to "argon2id",
            "mem" to params.memoryKib,
            "iter" to params.iterations,
            "par" to params.parallelism,
            "salt" to b64(salt),
            "wrapNonce" to b64(wrapNonce),
            "wrapped" to b64(wrapped),
            "dataNonce" to b64(dataNonce),
            "data" to b64(data),
        )
    )

    private class Header(
        val params: KdfParams,
        val salt: ByteArray,
        val wrapNonce: ByteArray,
        val wrapped: ByteArray,
        val dataNonce: ByteArray,
        val data: ByteArray,
    )

    private fun parse(blob: String): Header {
        val m = runCatching { Json.parseObject(blob) }
            .getOrElse { throw VaultFormatException("vault is not valid JSON") }
        fun str(key: String): String =
            m[key] as? String ?: throw VaultFormatException("vault missing field '$key'")
        fun int(key: String, default: Int): Int = (m[key] as? Double)?.toInt() ?: default
        val version = int("v", 0)
        if (version != FORMAT_VERSION) throw VaultFormatException("unsupported vault version $version")
        return Header(
            params = KdfParams(
                memoryKib = int("mem", 65_536),
                iterations = int("iter", 3),
                parallelism = int("par", 1),
            ),
            salt = unb64(str("salt")),
            wrapNonce = unb64(str("wrapNonce")),
            wrapped = unb64(str("wrapped")),
            dataNonce = unb64(str("dataNonce")),
            data = unb64(str("data")),
        )
    }

    // --- helpers -------------------------------------------------------------

    private fun randomBytes(n: Int): ByteArray = ByteArray(n).also(rng::nextBytes)

    private fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    private fun unb64(s: String): ByteArray =
        runCatching { Base64.getDecoder().decode(s) }
            .getOrElse { throw VaultFormatException("vault has invalid base64") }

    private fun charsToUtf8(chars: CharArray): ByteArray {
        val bb = Charsets.UTF_8.encode(java.nio.CharBuffer.wrap(chars))
        val out = ByteArray(bb.remaining())
        bb.get(out)
        return out
    }
}
