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

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.R
import com.ok1cdj.kauth.data.AutoLockMode

@Composable
fun SettingsDialog(
    autoLockMode: AutoLockMode,
    onAutoLockMode: (AutoLockMode) -> Unit,
    biometricAvailable: Boolean,
    biometricEnabled: Boolean,
    onEnableBiometric: () -> Unit,
    onDisableBiometric: () -> Unit,
    onChangePassword: () -> Unit,
    onExport: () -> Unit,
    onRestore: () -> Unit,
    autoBackupFolder: String?,
    onEnableAutoBackup: () -> Unit,
    onDisableAutoBackup: () -> Unit,
    onExportOtpauth: () -> Unit,
    onLock: () -> Unit,
    onDismiss: () -> Unit,
) {
    MmdDialog(onDismiss = onDismiss, modifier = Modifier.heightIn(max = 620.dp)) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState()),
        ) {
            TextMMD(text = stringResource(R.string.settings_title), fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(12.dp))

            // Auto-lock timing.
            TextMMD(text = stringResource(R.string.auto_lock_label), fontSize = 15.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                SegmentButton(stringResource(R.string.auto_lock_immediate), autoLockMode == AutoLockMode.IMMEDIATE, Modifier.weight(1f)) { onAutoLockMode(AutoLockMode.IMMEDIATE) }
                SegmentButton(stringResource(R.string.auto_lock_1min), autoLockMode == AutoLockMode.ONE_MIN, Modifier.weight(1f)) { onAutoLockMode(AutoLockMode.ONE_MIN) }
                SegmentButton(stringResource(R.string.auto_lock_5min), autoLockMode == AutoLockMode.FIVE_MIN, Modifier.weight(1f)) { onAutoLockMode(AutoLockMode.FIVE_MIN) }
                SegmentButton(stringResource(R.string.auto_lock_never), autoLockMode == AutoLockMode.NEVER, Modifier.weight(1f)) { onAutoLockMode(AutoLockMode.NEVER) }
            }

            Spacer(Modifier.height(12.dp))
            // Biometric unlock — only when the device supports it.
            if (biometricAvailable) {
                if (biometricEnabled) {
                    ActionRow(stringResource(R.string.biometric_disable), stringResource(R.string.biometric_disable_sub), onDisableBiometric)
                } else {
                    ActionRow(stringResource(R.string.biometric_enable), stringResource(R.string.biometric_enable_sub), onEnableBiometric)
                }
                Spacer(Modifier.height(8.dp))
            }

            ActionRow(stringResource(R.string.change_password), stringResource(R.string.change_password_sub), onChangePassword)
            Spacer(Modifier.height(8.dp))
            ActionRow(stringResource(R.string.export_backup), stringResource(R.string.export_backup_sub), onExport)
            Spacer(Modifier.height(8.dp))
            ActionRow(stringResource(R.string.restore_backup), stringResource(R.string.restore_backup_sub), onRestore)
            Spacer(Modifier.height(8.dp))
            // Automatic backup — tap to pick a folder when off, tap to stop when on.
            if (autoBackupFolder != null) {
                ActionRow(stringResource(R.string.auto_backup), stringResource(R.string.auto_backup_on_sub, autoBackupFolder), onDisableAutoBackup)
            } else {
                ActionRow(stringResource(R.string.auto_backup), stringResource(R.string.auto_backup_off_sub), onEnableAutoBackup)
            }
            Spacer(Modifier.height(8.dp))
            ActionRow(stringResource(R.string.export_otpauth), stringResource(R.string.export_otpauth_sub), onExportOtpauth)
        }

        Spacer(Modifier.height(16.dp))
        MmdButton(stringResource(R.string.lock_now), modifier = Modifier.fillMaxWidth(), onClick = onLock)
        Spacer(Modifier.height(8.dp))
        MmdButton(stringResource(R.string.close), modifier = Modifier.fillMaxWidth(), onClick = onDismiss)
    }
}

@Composable
private fun ActionRow(title: String, sub: String, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color.Black, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(12.dp),
    ) {
        TextMMD(text = title, fontSize = 15.sp, fontWeight = FontWeight.Bold)
        TextMMD(text = sub, fontSize = 11.sp)
    }
}
