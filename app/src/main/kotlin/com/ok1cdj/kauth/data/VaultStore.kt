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

private val Context.dataStore by preferencesDataStore(name = "vault")

/**
 * Persists the single encrypted vault blob (see
 * `com.ok1cdj.kauth.core.VaultCrypto`) via Preferences DataStore. Only ciphertext
 * is ever stored — the plaintext accounts and the master password never touch
 * disk. The stored string is exactly the same format written to backup files, so
 * the two share one code path.
 */
class VaultStore(private val context: Context) {

    /** The stored encrypted vault, or `null` on a fresh install. */
    suspend fun loadBlob(): String? =
        context.dataStore.data.first()[VAULT]

    suspend fun saveBlob(blob: String) {
        context.dataStore.edit { it[VAULT] = blob }
    }

    /** Whether a vault has been created yet (drives first-run setup vs. unlock). */
    suspend fun hasVault(): Boolean = loadBlob() != null

    private companion object {
        val VAULT = stringPreferencesKey("vault")
    }
}
