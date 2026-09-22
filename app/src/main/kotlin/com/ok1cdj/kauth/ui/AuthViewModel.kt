/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.ok1cdj.kauth.ui

import android.app.Application
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.ok1cdj.kauth.core.GaMigration
import com.ok1cdj.kauth.core.MergeResult
import com.ok1cdj.kauth.core.OtpAccount
import com.ok1cdj.kauth.core.OtpUri
import com.ok1cdj.kauth.core.VaultCrypto
import com.ok1cdj.kauth.core.VaultFormatException
import com.ok1cdj.kauth.core.VaultModel
import com.ok1cdj.kauth.core.WrongPasswordException
import com.ok1cdj.kauth.data.AutoLockMode
import com.ok1cdj.kauth.data.BiometricMaterial
import com.ok1cdj.kauth.data.SettingsStore
import com.ok1cdj.kauth.data.VaultStore
import com.ok1cdj.kauth.security.BiometricVault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Which screen is showing. State-based navigation, no Compose Navigation. */
sealed interface Screen {
    data object Loading : Screen
    data object Setup : Screen        // first-run: create master password
    data object Unlock : Screen       // enter master password
    data object Accounts : Screen     // the code list
    data object AddChooser : Screen   // scan / paste / manual
    data object Manual : Screen       // manual entry form
    data object Paste : Screen        // paste otpauth text
    data object Scan : Screen         // one-shot camera capture
    data object Import : Screen       // review a Google Authenticator import
}

/** What happened when some scanned/pasted text was consumed. */
sealed interface TextResult {
    data class Added(val account: OtpAccount) : TextResult   // single otpauth:// account
    data object ImportUpdated : TextResult                   // migration part accumulated
    data object Invalid : TextResult                         // not an otpauth link
}

/** Summary shown after a Google Authenticator import completes. */
data class ImportSummary(val added: Int, val skipped: Int, val failed: Int)

/** Outcome of a backup restore. */
sealed interface RestoreResult {
    data class Ok(val added: Int, val skipped: Int) : RestoreResult
    data object WrongPassword : RestoreResult
    data object BadFile : RestoreResult
}

/**
 * Single source of truth for the whole app: navigation, the unlocked account list
 * and the **vault master key (VMK)** — held in memory only while unlocked and
 * wiped on [lock]. Holding the VMK (rather than the password) makes saves cheap
 * (no Argon2 per write) and lets password unlock and biometric unlock share one
 * path.
 */
class AuthViewModel(app: Application) : AndroidViewModel(app) {

    private val store = VaultStore(app)
    private val settings = SettingsStore(app)
    private val saveMutex = Mutex()

    /** The vault master key — kept in memory only while unlocked, zeroed on lock. */
    private var vmk: ByteArray? = null

    /** The current encrypted vault blob (ciphertext; safe to keep in memory). */
    private var currentBlob: String? = null

    var screen: Screen by mutableStateOf(Screen.Loading)
        private set

    var accounts: List<OtpAccount> by mutableStateOf(emptyList())
        private set

    /** Set true after a failed unlock; cleared on the next attempt. */
    var unlockError: Boolean by mutableStateOf(false)
        private set

    /** True while a slow KDF operation (create / unlock / change password) runs,
     *  so the UI can show progress instead of appearing frozen. */
    var busy: Boolean by mutableStateOf(false)
        private set

    // --- settings / biometric ------------------------------------------------
    var autoLockMode: AutoLockMode by mutableStateOf(AutoLockMode.IMMEDIATE)
        private set
    var biometricEnabled: Boolean by mutableStateOf(false)
        private set
    var biometricMaterial: BiometricMaterial? by mutableStateOf(null)
        private set

    // Auto-lock policy lives here (not in the Activity). Backgrounding a SAF
    // picker or a biometric prompt must not auto-lock; callers bracket those with
    // [beginSensitiveOp]/[endSensitiveOp]. A counter (not a bare flag) so
    // overlapping ops don't clear each other, and [onEnterForeground] force-clears
    // it so a callback-less dismissal can't leave auto-lock disabled.
    private var autoLockSuspends = 0

    /** Monotonic time the app was last backgrounded (for timed auto-lock). */
    private var backgroundedAt: Long? = null

    // --- pending Google Authenticator import ---------------------------------
    var pendingImport: List<OtpAccount> by mutableStateOf(emptyList())
        private set
    var importFailures: List<String> by mutableStateOf(emptyList())
        private set
    var importBatchIndex: Int by mutableStateOf(0)
        private set
    var importBatchSize: Int by mutableStateOf(1)
        private set

    /** Non-null when an import just finished; the Accounts screen shows it once. */
    var importSummary: ImportSummary? by mutableStateOf(null)
        private set

    val isUnlocked: Boolean get() = vmk != null

    init {
        viewModelScope.launch {
            currentBlob = store.loadBlob()
            autoLockMode = settings.loadAutoLockMode()
            biometricMaterial = settings.loadBiometric()
            biometricEnabled = biometricMaterial != null
            screen = if (currentBlob != null) Screen.Unlock else Screen.Setup
        }
    }

    // --- lock / unlock -------------------------------------------------------

    /** Create the vault with a new master password (first run). */
    fun createVault(password: String) {
        if (busy) return
        val pw = password.toCharArray()
        busy = true
        viewModelScope.launch {
            try {
                val sealed = withContext(Dispatchers.Default) {
                    VaultCrypto.create(VaultModel.serialize(emptyList()).toByteArray(Charsets.UTF_8), pw)
                }
                store.saveBlob(sealed.blob)
                currentBlob = sealed.blob
                vmk = sealed.vmk
                accounts = emptyList()
                screen = Screen.Accounts
            } finally {
                busy = false
            }
        }
    }

    /** Attempt to unlock with the master [password]. */
    fun unlock(password: String) {
        if (busy) return
        unlockError = false
        val pw = password.toCharArray()
        busy = true
        viewModelScope.launch {
            try {
                val blob = currentBlob ?: store.loadBlob()?.also { currentBlob = it }
                if (blob == null) { screen = Screen.Setup; return@launch }
                val result = withContext(Dispatchers.Default) {
                    runCatching {
                        val key = VaultCrypto.unlock(blob, pw)
                        key to VaultCrypto.decryptData(blob, key)
                    }
                }
                result.onSuccess { (key, bytes) ->
                    vmk = key
                    accounts = VaultModel.deserialize(String(bytes, Charsets.UTF_8))
                    screen = Screen.Accounts
                }.onFailure {
                    unlockError = true // WrongPassword or a corrupt vault
                }
            } finally {
                busy = false
            }
        }
    }

    /**
     * Unlock via a VMK recovered by biometrics. Copies [key] immediately (the
     * caller may zero its array right after) and does the decrypt/parse off the
     * main thread; [onResult] reports success on the main thread.
     */
    fun unlockWithVmk(key: ByteArray, onResult: (Boolean) -> Unit) {
        val blob = currentBlob ?: run { onResult(false); return }
        val keyCopy = key.copyOf()
        viewModelScope.launch {
            val decoded = withContext(Dispatchers.Default) {
                runCatching { VaultCrypto.decryptData(blob, keyCopy) }
            }
            decoded.onSuccess { bytes ->
                vmk = keyCopy
                accounts = VaultModel.deserialize(String(bytes, Charsets.UTF_8))
                screen = Screen.Accounts
                onResult(true)
            }.onFailure {
                keyCopy.fill(0)
                onResult(false)
            }
        }
    }

    /** Wipe the in-memory secrets and return to the lock screen. */
    fun lock() {
        vmk?.fill(0)
        vmk = null
        accounts = emptyList()
        clearImport()
        importSummary = null
        backgroundedAt = null
        screen = Screen.Unlock
    }

    /** A copy of the current session VMK, for wrapping with a biometric key. */
    fun sessionVmk(): ByteArray? = vmk?.copyOf()

    // --- auto-lock lifecycle (driven by the Activity's lifecycle observer) ----

    /** Bracket a SAF picker / biometric prompt so backgrounding it won't lock. */
    fun beginSensitiveOp() { autoLockSuspends++ }
    fun endSensitiveOp() { if (autoLockSuspends > 0) autoLockSuspends-- }

    /** App left the foreground: lock now (IMMEDIATE) or stamp the time (timed). */
    fun onEnterBackground() {
        if (!isUnlocked || autoLockSuspends > 0) return
        if (autoLockMode == AutoLockMode.IMMEDIATE) lock()
        else backgroundedAt = SystemClock.elapsedRealtime()
    }

    /** App returned: lock if it was away past the timed threshold. */
    fun onEnterForeground() {
        if (isUnlocked && autoLockSuspends == 0) {
            val bg = backgroundedAt
            if (bg != null && SystemClock.elapsedRealtime() - bg >= autoLockMode.thresholdMs()) lock()
        }
        backgroundedAt = null
        // A returned foreground means any system UI we launched is finished; clear
        // any suspend a callback-less dismissal may have left dangling (self-heal).
        autoLockSuspends = 0
    }

    // --- navigation ----------------------------------------------------------

    fun showAccounts() { screen = Screen.Accounts }
    fun showAddChooser() { screen = Screen.AddChooser }
    fun showManual() { screen = Screen.Manual }
    fun showPaste() { screen = Screen.Paste }
    fun showScan() { screen = Screen.Scan }
    fun consumeImportSummary() { importSummary = null }

    // --- account mutations ---------------------------------------------------

    fun addAccount(account: OtpAccount) {
        accounts = accounts + account
        persist()
        screen = Screen.Accounts
    }

    fun deleteAccount(account: OtpAccount) {
        accounts = accounts.filterNot { it === account || it == account }
        persist()
    }

    /** Advance an HOTP account's counter and persist. */
    fun advanceHotp(account: OtpAccount) {
        accounts = accounts.map { if (it == account) it.copy(counter = it.counter + 1) else it }
        persist()
    }

    // --- consuming scanned / pasted text -------------------------------------

    /**
     * Handle a QR/clipboard string. A single `otpauth://` account is added
     * immediately; a `otpauth-migration://` payload is decoded and accumulated
     * into the pending import (supporting multi-part exports).
     */
    fun consumeText(text: String): TextResult {
        val trimmed = text.trim()
        return when {
            GaMigration.isMigration(trimmed) -> {
                val result = GaMigration.decode(trimmed)
                // Accumulate into the pending import, de-duplicating within the batch
                // and against the live vault.
                val existing = (accounts + pendingImport).mapTo(HashSet()) { it.dedupeKey() }
                val fresh = result.accounts.filter { existing.add(it.dedupeKey()) }
                pendingImport = pendingImport + fresh
                importFailures = importFailures + result.failures
                importBatchIndex = result.batchIndex
                importBatchSize = result.batchSize
                screen = Screen.Import
                TextResult.ImportUpdated
            }
            OtpUri.isOtpAuth(trimmed) -> {
                val account = runCatching { OtpUri.parse(trimmed) }.getOrNull()
                    ?: return TextResult.Invalid
                TextResult.Added(account)
            }
            else -> TextResult.Invalid
        }
    }

    // --- Google Authenticator import review ----------------------------------

    /** Merge the pending import into the vault and produce a summary. */
    fun finishImport() {
        val result: MergeResult = VaultModel.merge(accounts, pendingImport)
        val failed = importFailures.size
        val skipped = result.skipped
        val added = result.added
        accounts = result.accounts
        persist()
        importSummary = ImportSummary(added = added, skipped = skipped, failed = failed)
        clearImport()
        screen = Screen.Accounts
    }

    fun cancelImport() {
        clearImport()
        screen = Screen.Accounts
    }

    private fun clearImport() {
        pendingImport = emptyList()
        importFailures = emptyList()
        importBatchIndex = 0
        importBatchSize = 1
    }

    // --- master password change ----------------------------------------------

    /**
     * Change the master password. [current] must open the current vault. The VMK
     * is re-wrapped under the new password; the data ciphertext and the biometric
     * wrap of the same VMK stay valid.
     */
    fun changePassword(current: String, newPassword: String, onResult: (Boolean) -> Unit) {
        val blob = currentBlob
        // Copy the VMK: a concurrent lock() (auto-lock) zeroes the live array, and
        // the Argon2 validation below is a long window — rewrapping a zeroed key
        // would brick the vault while reporting success.
        val key = vmk?.copyOf()
        if (blob == null || key == null) { onResult(false); return }
        val newPw = newPassword.toCharArray()
        busy = true
        viewModelScope.launch {
            try {
                val ok = withContext(Dispatchers.Default) {
                    runCatching { VaultCrypto.unlock(blob, current.toCharArray()) }.isSuccess
                }
                if (!ok) { onResult(false); return@launch }
                // Serialize with persist() so the rewrapped header isn't clobbered.
                saveMutex.withLock {
                    val base = currentBlob ?: blob
                    val newBlob = withContext(Dispatchers.Default) { VaultCrypto.rewrap(base, key, newPw) }
                    store.saveBlob(newBlob)
                    currentBlob = newBlob
                }
                onResult(true)
            } finally {
                key.fill(0)
                newPw.fill(' ')
                busy = false
            }
        }
    }

    // --- biometric enable / disable ------------------------------------------

    fun onBiometricEnabled(material: BiometricMaterial) {
        biometricMaterial = material
        biometricEnabled = true
        viewModelScope.launch { settings.saveBiometric(material) }
    }

    fun disableBiometric() {
        BiometricVault.deleteKey()
        biometricMaterial = null
        biometricEnabled = false
        viewModelScope.launch { settings.clearBiometric() }
    }

    fun updateAutoLock(mode: AutoLockMode) {
        autoLockMode = mode
        viewModelScope.launch { settings.saveAutoLockMode(mode) }
    }

    // --- backup --------------------------------------------------------------

    /**
     * Produce an encrypted backup blob of the current vault. Reseals the latest
     * accounts under the session VMK so the export always reflects the live state.
     * The result is password-wrapped and portable — no biometric material.
     */
    suspend fun exportBlob(): String? {
        val blob = currentBlob ?: return null
        val key = vmk ?: return null
        return withContext(Dispatchers.Default) {
            VaultCrypto.resealData(blob, key, VaultModel.serialize(accounts).toByteArray(Charsets.UTF_8))
        }
    }

    /**
     * Restore from an encrypted backup: open [blob] with [backupPassword], then
     * merge into the current vault (skipping exact duplicates).
     */
    suspend fun restore(blob: String, backupPassword: String): RestoreResult {
        // Must be unlocked: restore mutates the in-memory list and persist() only
        // writes when the VMK is present. Without this guard a restore run while
        // locked would report success but silently save nothing.
        if (vmk == null || currentBlob == null) return RestoreResult.BadFile
        val decoded = withContext(Dispatchers.Default) {
            runCatching {
                val key = VaultCrypto.unlock(blob, backupPassword.toCharArray())
                VaultCrypto.decryptData(blob, key)
            }
        }
        val bytes = decoded.getOrElse { e ->
            return when (e) {
                is WrongPasswordException -> RestoreResult.WrongPassword
                is VaultFormatException -> RestoreResult.BadFile
                else -> RestoreResult.BadFile
            }
        }
        val incoming = VaultModel.deserialize(String(bytes, Charsets.UTF_8))
        val merged = VaultModel.merge(accounts, incoming)
        accounts = merged.accounts
        persist()
        return RestoreResult.Ok(merged.added, merged.skipped)
    }

    // --- persistence ---------------------------------------------------------

    /** Reseal the data under the session VMK (no KDF) and store it. */
    private fun persist() {
        // Copy the VMK: the reseal runs on a background coroutine, and a concurrent
        // lock() (auto-lock / "Lock now") zeroes the live array — resealing under a
        // zeroed key would encrypt the vault so no password can ever open it.
        val key = vmk?.copyOf() ?: return
        val snapshot = accounts
        viewModelScope.launch {
            try {
                saveMutex.withLock {
                    // Read the blob inside the lock so a concurrent password change
                    // (which rewrites the header) is never clobbered by a stale reseal.
                    val blob = currentBlob ?: return@withLock
                    val newBlob = withContext(Dispatchers.Default) {
                        VaultCrypto.resealData(blob, key, VaultModel.serialize(snapshot).toByteArray(Charsets.UTF_8))
                    }
                    store.saveBlob(newBlob)
                    currentBlob = newBlob
                }
            } finally {
                key.fill(0)
            }
        }
    }

    override fun onCleared() {
        vmk?.fill(0)
        vmk = null
    }
}
