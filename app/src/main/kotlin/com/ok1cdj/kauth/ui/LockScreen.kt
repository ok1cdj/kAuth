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

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.R
import com.ok1cdj.kauth.core.PasswordStrength
import com.ok1cdj.kauth.core.PasswordStrength.Level

/** Unlock an existing vault. */
@Composable
fun UnlockScreen(
    error: Boolean,
    busy: Boolean = false,
    biometricEnabled: Boolean = false,
    onUnlock: (String) -> Unit,
    onBiometric: () -> Unit = {},
) {
    var password by remember { mutableStateOf("") }

    // When biometrics is set up, prompt automatically on arrival; the password
    // field stays available as the fallback. Guarded so a config-change
    // recomposition doesn't re-summon the prompt after the user dismissed it.
    // rememberSaveable is dropped when this screen leaves composition, so the next
    // fresh lock still auto-prompts.
    var alreadyPrompted by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(biometricEnabled) {
        if (biometricEnabled && !alreadyPrompted) {
            alreadyPrompted = true
            onBiometric()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(40.dp))
        Image(
            painter = painterResource(R.drawable.ic_launcher_foreground),
            contentDescription = null,
            modifier = Modifier.size(96.dp),
        )
        Spacer(Modifier.height(8.dp))
        TextMMD(text = stringResource(R.string.unlock_title), fontSize = 32.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(24.dp))
        TextMMD(text = stringResource(R.string.unlock_prompt), fontSize = 14.sp)
        Spacer(Modifier.height(12.dp))
        EinkTextField(
            value = password,
            onValueChange = { password = it },
            label = stringResource(R.string.setup_password_hint),
            isPassword = true,
        )
        if (error) {
            Spacer(Modifier.height(8.dp))
            TextMMD(text = stringResource(R.string.unlock_wrong_password), fontSize = 13.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(20.dp))
        MmdButton(
            text = stringResource(if (busy) R.string.unlocking else R.string.unlock_button),
            modifier = Modifier.fillMaxWidth(),
            enabled = password.isNotEmpty() && !busy,
            onClick = { onUnlock(password) },
        )
        if (biometricEnabled) {
            Spacer(Modifier.height(8.dp))
            MmdButton(
                text = stringResource(R.string.unlock_biometric),
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
                onClick = onBiometric,
            )
        }
    }
}

/** First-run: create the master password. */
@Composable
fun SetupScreen(busy: Boolean = false, onCreate: (String) -> Unit) {
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }

    val level = remember(password) { if (password.isEmpty()) Level.TOO_SHORT else PasswordStrength.evaluate(password) }
    val acceptable = PasswordStrength.isAcceptable(password)
    val matches = password == confirm
    val canCreate = acceptable && matches

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
    ) {
        Spacer(Modifier.height(20.dp))
        Image(
            painter = painterResource(R.drawable.ic_launcher_foreground),
            contentDescription = null,
            modifier = Modifier.size(72.dp).align(Alignment.CenterHorizontally),
        )
        Spacer(Modifier.height(12.dp))
        TextMMD(text = stringResource(R.string.setup_title), fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(10.dp))
        TextMMD(text = stringResource(R.string.setup_intro), fontSize = 13.sp)
        Spacer(Modifier.height(20.dp))

        EinkTextField(
            value = password,
            onValueChange = { password = it },
            label = stringResource(R.string.setup_password_hint),
            isPassword = true,
        )
        Spacer(Modifier.height(8.dp))
        StrengthMeter(level)

        Spacer(Modifier.height(12.dp))
        EinkTextField(
            value = confirm,
            onValueChange = { confirm = it },
            label = stringResource(R.string.setup_confirm_hint),
            isPassword = true,
        )

        // Fixed-height slot so showing/hiding the validation message never shifts
        // the Create button down (it used to push the button below the fold).
        Spacer(Modifier.height(8.dp))
        Box(modifier = Modifier.fillMaxWidth().heightIn(min = 40.dp)) {
            when {
                password.isNotEmpty() && !acceptable ->
                    TextMMD(
                        text = stringResource(R.string.setup_password_too_weak, PasswordStrength.MIN_LENGTH),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                    )
                confirm.isNotEmpty() && !matches ->
                    TextMMD(text = stringResource(R.string.setup_password_mismatch), fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }

        Spacer(Modifier.height(12.dp))
        MmdButton(
            text = stringResource(if (busy) R.string.creating else R.string.setup_create_button),
            modifier = Modifier.fillMaxWidth(),
            enabled = canCreate && !busy,
            onClick = { onCreate(password) },
        )
    }
}

/** A discrete four-segment strength bar plus a word — no animation, e-ink safe. */
@Composable
private fun StrengthMeter(level: Level) {
    val filled = when (level) {
        Level.TOO_SHORT -> 0
        Level.WEAK -> 1
        Level.FAIR -> 2
        Level.GOOD -> 3
        Level.STRONG -> 4
    }
    val word = stringResource(
        when (level) {
            Level.TOO_SHORT -> R.string.strength_too_short
            Level.WEAK -> R.string.strength_weak
            Level.FAIR -> R.string.strength_fair
            Level.GOOD -> R.string.strength_good
            Level.STRONG -> R.string.strength_strong
        }
    )
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        for (i in 0 until 4) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(10.dp)
                    .border(1.dp, Color.Black)
                    .background(if (i < filled) Color.Black else Color.White),
            )
        }
    }
    Spacer(Modifier.height(4.dp))
    TextMMD(text = stringResource(R.string.strength_label, word), fontSize = 12.sp)
}
