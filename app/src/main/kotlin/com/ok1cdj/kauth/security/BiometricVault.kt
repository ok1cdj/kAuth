/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.ok1cdj.kauth.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.ok1cdj.kauth.data.BiometricMaterial
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Optional biometric unlock: an Android Keystore key (biometric-bound) wraps the
 * same vault master key (VMK) the password protects. Enabling stores the VMK
 * encrypted under this device key; unlocking recovers the VMK after a biometric
 * prompt. The master password always remains the ultimate fallback, and the
 * wrapped VMK is device-local (never exported in a backup).
 */
object BiometricVault {

    private const val KEY_ALIAS = "kauth_bio"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val TAG_BITS = 128
    private const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG

    /** True if this device has usable strong biometrics enrolled. */
    fun isAvailable(context: Context): Boolean =
        BiometricManager.from(context).canAuthenticate(AUTHENTICATORS) ==
            BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Prompt for biometrics, then wrap [vmk] with a freshly created device key.
     * On success [onSuccess] receives the ciphertext+IV to persist.
     */
    fun enable(
        activity: FragmentActivity,
        vmk: ByteArray,
        title: String,
        subtitle: String,
        cancel: String,
        onSuccess: (BiometricMaterial) -> Unit,
        onError: (String) -> Unit,
    ) {
        deleteKey() // start from a clean key each time enable is invoked
        val cipher = try {
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, createKey()) }
        } catch (e: Exception) {
            onError(e.message ?: "keystore error"); return
        }
        authenticate(activity, cipher, title, subtitle, cancel,
            onSuccess = { authedCipher ->
                runCatching {
                    val ct = authedCipher.doFinal(vmk)
                    BiometricMaterial(b64(ct), b64(authedCipher.iv))
                }.onSuccess(onSuccess).onFailure { onError(it.message ?: "encrypt failed") }
            },
            onError = onError,
        )
    }

    /**
     * Prompt for biometrics, then unwrap the VMK from [material]. If the key was
     * invalidated (e.g. a new fingerprint was enrolled) [onInvalidated] fires so
     * the caller can fall back to the password and clear the stale material.
     */
    fun unlock(
        activity: FragmentActivity,
        material: BiometricMaterial,
        title: String,
        subtitle: String,
        cancel: String,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
        onInvalidated: () -> Unit,
    ) {
        val key = loadKey()
        if (key == null) { onInvalidated(); return }
        val cipher = try {
            Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, unb64(material.iv)))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            onInvalidated(); return
        } catch (e: Exception) {
            onError(e.message ?: "keystore error"); return
        }
        authenticate(activity, cipher, title, subtitle, cancel,
            onSuccess = { authedCipher ->
                runCatching { authedCipher.doFinal(unb64(material.ciphertext)) }
                    .onSuccess(onSuccess)
                    .onFailure { onError(it.message ?: "decrypt failed") }
            },
            onError = onError,
        )
    }

    /** Remove the Keystore key (called when the user disables biometric unlock). */
    fun deleteKey() {
        runCatching {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(KEY_ALIAS)
        }
    }

    // --- internals -----------------------------------------------------------

    private fun authenticate(
        activity: FragmentActivity,
        cipher: Cipher,
        title: String,
        subtitle: String,
        cancel: String,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit,
    ) {
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c != null) onSuccess(c) else onError("no cipher")
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(cancel)
            .setAllowedAuthenticators(AUTHENTICATORS)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    private fun createKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                // A new biometric enrollment invalidates the key — fail closed and
                // fall back to the password rather than trusting a changed sensor set.
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun loadKey(): SecretKey? = runCatching {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        ks.getKey(KEY_ALIAS, null) as? SecretKey
    }.getOrNull()

    private fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
    private fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)
}
