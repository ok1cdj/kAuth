/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.ok1cdj.kauth.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first

/** When the vault auto-locks after leaving the foreground. */
enum class AutoLockMode {
    IMMEDIATE, ONE_MIN, FIVE_MIN, NEVER;

    /** Idle threshold in milliseconds; 0 = lock immediately, Long.MAX_VALUE = never. */
    fun thresholdMs(): Long = when (this) {
        IMMEDIATE -> 0L
        ONE_MIN -> 60_000L
        FIVE_MIN -> 300_000L
        NEVER -> Long.MAX_VALUE
    }

    companion object {
        fun from(name: String?): AutoLockMode =
            entries.firstOrNull { it.name == name } ?: IMMEDIATE
    }
}

/** The device-local biometric wrapping of the VMK (ciphertext + GCM IV, base64). */
data class BiometricMaterial(val ciphertext: String, val iv: String)

private val Context.settingsStore by preferencesDataStore(name = "settings")

/**
 * Non-secret app preferences plus the device-local biometric key material.
 *
 * The biometric material is the VMK encrypted by an Android Keystore key — it is
 * ciphertext, bound to this device, and is **deliberately kept out of the vault
 * blob** so exported backups stay password-only and portable.
 */
class SettingsStore(private val context: Context) {

    suspend fun loadAutoLockMode(): AutoLockMode =
        AutoLockMode.from(context.settingsStore.data.first()[AUTO_LOCK])

    suspend fun saveAutoLockMode(mode: AutoLockMode) {
        context.settingsStore.edit { it[AUTO_LOCK] = mode.name }
    }

    suspend fun loadBiometric(): BiometricMaterial? {
        val prefs = context.settingsStore.data.first()
        val ct = prefs[BIO_CT] ?: return null
        val iv = prefs[BIO_IV] ?: return null
        return BiometricMaterial(ct, iv)
    }

    suspend fun saveBiometric(material: BiometricMaterial) {
        context.settingsStore.edit {
            it[BIO_CT] = material.ciphertext
            it[BIO_IV] = material.iv
        }
    }

    suspend fun clearBiometric() {
        context.settingsStore.edit {
            it.remove(BIO_CT)
            it.remove(BIO_IV)
        }
    }

    private companion object {
        val AUTO_LOCK = stringPreferencesKey("auto_lock_mode")
        val BIO_CT = stringPreferencesKey("bio_ct")
        val BIO_IV = stringPreferencesKey("bio_iv")
    }
}
