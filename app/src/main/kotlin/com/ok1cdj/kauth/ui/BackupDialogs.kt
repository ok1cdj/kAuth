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

import android.widget.Toast
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.R
import com.ok1cdj.kauth.core.PasswordStrength
import kotlinx.coroutines.launch

/** Change the master password (verifies the current one, re-encrypts the vault). */
@Composable
fun ChangePasswordDialog(vm: AuthViewModel, onDismiss: () -> Unit) {
    val context = LocalContext.current
    var current by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var wrongCurrent by remember { mutableStateOf(false) }

    val acceptable = PasswordStrength.isAcceptable(newPassword)
    val matches = newPassword == confirm
    val canSubmit = current.isNotEmpty() && acceptable && matches

    MmdDialog(onDismiss = onDismiss) {
        TextMMD(text = stringResource(R.string.change_password_title), fontSize = 18.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(12.dp))
        EinkTextField(current, { current = it; wrongCurrent = false }, stringResource(R.string.current_password), isPassword = true)
        Spacer(Modifier.height(8.dp))
        EinkTextField(newPassword, { newPassword = it }, stringResource(R.string.new_password), isPassword = true)
        Spacer(Modifier.height(8.dp))
        EinkTextField(confirm, { confirm = it }, stringResource(R.string.confirm_new_password), isPassword = true)

        Spacer(Modifier.height(8.dp))
        when {
            wrongCurrent ->
                TextMMD(text = stringResource(R.string.change_password_wrong), fontSize = 12.sp, fontWeight = FontWeight.Bold)
            newPassword.isNotEmpty() && !acceptable ->
                TextMMD(text = stringResource(R.string.setup_password_too_weak, PasswordStrength.MIN_LENGTH), fontSize = 12.sp, fontWeight = FontWeight.Bold)
            confirm.isNotEmpty() && !matches ->
                TextMMD(text = stringResource(R.string.setup_password_mismatch), fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }

        Spacer(Modifier.height(12.dp))
        MmdButton(
            text = stringResource(R.string.change_password_button),
            modifier = Modifier.fillMaxWidth(),
            enabled = canSubmit,
            onClick = {
                vm.changePassword(current, newPassword) { ok ->
                    if (ok) {
                        Toast.makeText(context, R.string.change_password_done, Toast.LENGTH_SHORT).show()
                        onDismiss()
                    } else {
                        wrongCurrent = true
                    }
                }
            },
        )
        Spacer(Modifier.height(8.dp))
        MmdButton(stringResource(R.string.cancel), modifier = Modifier.fillMaxWidth(), onClick = onDismiss)
    }
}

/** Prompt for the backup's password, then merge it into the current vault. */
@Composable
fun RestoreDialog(vm: AuthViewModel, blob: String, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var errorRes by remember { mutableStateOf<Int?>(null) }
    var busy by remember { mutableStateOf(false) }

    MmdDialog(onDismiss = onDismiss) {
        TextMMD(text = stringResource(R.string.restore_title), fontSize = 18.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(12.dp))
        EinkTextField(password, { password = it; errorRes = null }, stringResource(R.string.restore_password), isPassword = true)
        errorRes?.let {
            Spacer(Modifier.height(8.dp))
            TextMMD(text = stringResource(it), fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(12.dp))
        MmdButton(
            text = stringResource(R.string.restore_button),
            modifier = Modifier.fillMaxWidth(),
            enabled = password.isNotEmpty() && !busy,
            onClick = {
                busy = true
                scope.launch {
                    when (val result = vm.restore(blob, password)) {
                        is RestoreResult.Ok -> {
                            Toast.makeText(
                                context,
                                context.getString(R.string.restore_result, result.added, result.skipped),
                                Toast.LENGTH_LONG,
                            ).show()
                            onDismiss()
                        }
                        RestoreResult.WrongPassword -> { errorRes = R.string.restore_wrong_password; busy = false }
                        RestoreResult.BadFile -> { errorRes = R.string.restore_bad_file; busy = false }
                    }
                }
            },
        )
        Spacer(Modifier.height(8.dp))
        MmdButton(stringResource(R.string.cancel), modifier = Modifier.fillMaxWidth(), onClick = onDismiss)
    }
}
