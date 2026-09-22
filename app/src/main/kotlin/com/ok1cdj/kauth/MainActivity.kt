/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.ok1cdj.kauth

import android.content.Context
import android.content.ContextWrapper
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.security.BiometricVault
import com.ok1cdj.kauth.ui.AboutDialog
import com.ok1cdj.kauth.ui.AccountsScreen
import com.ok1cdj.kauth.ui.AddChooserScreen
import com.ok1cdj.kauth.ui.AuthViewModel
import com.ok1cdj.kauth.ui.ChangePasswordDialog
import com.ok1cdj.kauth.ui.ImportReviewScreen
import com.ok1cdj.kauth.ui.KAuthTheme
import com.ok1cdj.kauth.ui.ManualEntryScreen
import com.ok1cdj.kauth.ui.MmdButton
import com.ok1cdj.kauth.ui.MmdDialog
import com.ok1cdj.kauth.ui.PasteScreen
import com.ok1cdj.kauth.ui.RestoreDialog
import com.ok1cdj.kauth.ui.ScanScreen
import com.ok1cdj.kauth.ui.Screen
import com.ok1cdj.kauth.ui.SettingsDialog
import com.ok1cdj.kauth.ui.SetupScreen
import com.ok1cdj.kauth.ui.TextResult
import com.ok1cdj.kauth.ui.UnlockScreen
import kotlinx.coroutines.launch

// FragmentActivity (not plain ComponentActivity) is required by BiometricPrompt.
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The whole app shows secrets (codes and, on the manual screen, the raw
        // secret). Block screenshots and screen recording for the entire window.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContent { KAuthTheme { App() } }
    }
}

private const val BACKUP_FILENAME = "kauth-backup.kauth"

private fun Context.findActivity(): FragmentActivity? = when (this) {
    is FragmentActivity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

@Composable
private fun App() {
    val vm: AuthViewModel = viewModel()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var showAbout by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }
    var showChangePassword by remember { mutableStateOf(false) }
    var restoreBlob by remember { mutableStateOf<String?>(null) }

    val biometricAvailable = remember { BiometricVault.isAvailable(context) }

    // SAF: write the encrypted vault to a user-chosen file.
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        vm.endSensitiveOp()
        if (uri != null) {
            scope.launch {
                val blob = vm.exportBlob()
                val ok = blob != null && runCatching {
                    context.contentResolver.openOutputStream(uri)?.use { it.write(blob.toByteArray()) }
                }.isSuccess
                Toast.makeText(
                    context,
                    if (ok) R.string.export_done else R.string.export_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    // SAF: read a backup file, then prompt for its password.
    val restoreLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        vm.endSensitiveOp()
        if (uri != null) {
            scope.launch {
                val text = runCatching {
                    context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                }.getOrNull()
                if (text != null) restoreBlob = text
                else Toast.makeText(context, R.string.restore_bad_file, Toast.LENGTH_SHORT).show()
            }
        }
    }

    // Auto-lock: the policy lives in the ViewModel; the observer just forwards the
    // foreground/background transitions. SAF pickers and the biometric prompt
    // bracket themselves with begin/endSensitiveOp so they don't self-lock.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> vm.onEnterBackground()
                Lifecycle.Event.ON_START -> vm.onEnterForeground()
                else -> {}
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // System back mirrors in-screen navigation.
    when (vm.screen) {
        Screen.AddChooser, Screen.Manual, Screen.Paste, Screen.Scan -> BackHandler { vm.showAccounts() }
        Screen.Import -> BackHandler { vm.cancelImport() }
        else -> {} // Accounts / lock screens: default (exit)
    }

    // targetSdk 37 forces edge-to-edge; inset below the system bars.
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White)
            .systemBarsPadding(),
    ) {
        when (vm.screen) {
            Screen.Loading -> {}
            Screen.Setup -> SetupScreen(onCreate = vm::createVault)
            Screen.Unlock -> UnlockScreen(
                error = vm.unlockError,
                biometricEnabled = vm.biometricEnabled && biometricAvailable,
                onUnlock = vm::unlock,
                onBiometric = { promptBiometricUnlock(context, vm) },
            )
            Screen.Accounts -> AccountsScreen(
                accounts = vm.accounts,
                onAdd = vm::showAddChooser,
                onAbout = { showAbout = true },
                onSettings = { showSettings = true },
                onDelete = vm::deleteAccount,
                onAdvanceHotp = vm::advanceHotp,
            )
            Screen.AddChooser -> AddChooserScreen(
                onScan = vm::showScan,
                onPaste = vm::showPaste,
                onManual = vm::showManual,
                onBack = vm::showAccounts,
            )
            Screen.Manual -> ManualEntryScreen(onSave = vm::addAccount, onBack = vm::showAccounts)
            Screen.Paste -> PasteScreen(
                onSubmit = { text ->
                    when (val r = vm.consumeText(text)) {
                        is TextResult.Added -> { vm.addAccount(r.account); true }
                        TextResult.ImportUpdated -> true
                        TextResult.Invalid -> false
                    }
                },
                onBack = vm::showAccounts,
            )
            Screen.Scan -> ScanScreen(
                onResult = { text ->
                    when (val r = vm.consumeText(text)) {
                        is TextResult.Added -> vm.addAccount(r.account)
                        TextResult.ImportUpdated -> {}
                        TextResult.Invalid ->
                            Toast.makeText(context, R.string.scan_not_otp, Toast.LENGTH_SHORT).show()
                    }
                },
                onBack = vm::showAccounts,
            )
            Screen.Import -> ImportReviewScreen(
                pending = vm.pendingImport,
                failures = vm.importFailures,
                batchIndex = vm.importBatchIndex,
                batchSize = vm.importBatchSize,
                onScanMore = vm::showScan,
                onFinish = vm::finishImport,
                onCancel = vm::cancelImport,
            )
        }
    }

    if (showAbout) AboutDialog(onDismiss = { showAbout = false })

    if (showSettings) {
        SettingsDialog(
            autoLockMode = vm.autoLockMode,
            onAutoLockMode = vm::updateAutoLock,
            biometricAvailable = biometricAvailable,
            biometricEnabled = vm.biometricEnabled,
            onEnableBiometric = {
                showSettings = false
                promptBiometricEnable(context, vm)
            },
            onDisableBiometric = { vm.disableBiometric() },
            onChangePassword = { showSettings = false; showChangePassword = true },
            onExport = { showSettings = false; vm.beginSensitiveOp(); exportLauncher.launch(BACKUP_FILENAME) },
            onRestore = { showSettings = false; vm.beginSensitiveOp(); restoreLauncher.launch(arrayOf("*/*")) },
            onLock = { showSettings = false; vm.lock() },
            onDismiss = { showSettings = false },
        )
    }

    if (showChangePassword) {
        ChangePasswordDialog(vm = vm, onDismiss = { showChangePassword = false })
    }

    restoreBlob?.let { blob ->
        RestoreDialog(vm = vm, blob = blob, onDismiss = { restoreBlob = null })
    }

    // One-shot import summary after finishing a Google Authenticator import.
    vm.importSummary?.let { summary ->
        MmdDialog(onDismiss = vm::consumeImportSummary) {
            TextMMD(text = stringResource(R.string.import_summary_title), fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            TextMMD(
                text = stringResource(R.string.import_summary_body, summary.added, summary.skipped, summary.failed),
                fontSize = 14.sp,
            )
            Spacer(Modifier.height(16.dp))
            MmdButton(stringResource(R.string.close), modifier = Modifier.fillMaxWidth(), onClick = vm::consumeImportSummary)
        }
    }
}

/** Wrap the current session VMK with a biometric-bound key and remember it. */
private fun promptBiometricEnable(context: Context, vm: AuthViewModel) {
    val activity = context.findActivity() ?: return
    val vmk = vm.sessionVmk() ?: return
    vm.beginSensitiveOp()
    BiometricVault.enable(
        activity = activity,
        vmk = vmk,
        title = context.getString(R.string.bio_enable_title),
        subtitle = context.getString(R.string.bio_prompt_subtitle),
        cancel = context.getString(R.string.cancel),
        onSuccess = { material ->
            vmk.fill(0)
            vm.endSensitiveOp()
            vm.onBiometricEnabled(material)
            Toast.makeText(context, R.string.bio_enabled, Toast.LENGTH_SHORT).show()
        },
        onError = { msg ->
            vmk.fill(0)
            vm.endSensitiveOp()
            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
        },
    )
}

/** Recover the VMK via a biometric prompt and unlock the vault. */
private fun promptBiometricUnlock(context: Context, vm: AuthViewModel) {
    val activity = context.findActivity() ?: return
    val material = vm.biometricMaterial ?: return
    vm.beginSensitiveOp()
    BiometricVault.unlock(
        activity = activity,
        material = material,
        title = context.getString(R.string.bio_unlock_title),
        subtitle = context.getString(R.string.bio_prompt_subtitle),
        cancel = context.getString(R.string.cancel),
        onSuccess = { vmk ->
            vm.endSensitiveOp()
            // unlockWithVmk copies the key synchronously, so we can zero ours now.
            vm.unlockWithVmk(vmk) { ok ->
                if (!ok) Toast.makeText(context, R.string.bio_error, Toast.LENGTH_SHORT).show()
            }
            vmk.fill(0)
        },
        onError = { vm.endSensitiveOp() /* cancelled/transient — password remains available */ },
        onInvalidated = {
            vm.endSensitiveOp()
            vm.disableBiometric()
            Toast.makeText(context, R.string.bio_invalidated, Toast.LENGTH_LONG).show()
        },
    )
}
