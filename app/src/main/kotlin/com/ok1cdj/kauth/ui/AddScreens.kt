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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.R
import com.ok1cdj.kauth.core.Base32
import com.ok1cdj.kauth.core.OtpAccount
import com.ok1cdj.kauth.core.OtpAlgorithm
import com.ok1cdj.kauth.core.OtpType

/** The add-account chooser: scan / paste / manual. */
@Composable
fun AddChooserScreen(
    onScan: () -> Unit,
    onPaste: () -> Unit,
    onManual: () -> Unit,
    onBack: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Header(title = stringResource(R.string.add_title), onBack = onBack)
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            ChoiceCard(stringResource(R.string.add_scan), stringResource(R.string.add_scan_sub), onScan)
            ChoiceCard(stringResource(R.string.add_paste), stringResource(R.string.add_paste_sub), onPaste)
            ChoiceCard(stringResource(R.string.add_manual), stringResource(R.string.add_manual_sub), onManual)
        }
    }
}

@Composable
private fun ChoiceCard(title: String, sub: String, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color.Black, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(16.dp),
    ) {
        TextMMD(text = title, fontSize = 17.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(2.dp))
        TextMMD(text = sub, fontSize = 12.sp)
    }
}

/** Paste an otpauth:// or otpauth-migration:// link. */
@Composable
fun PasteScreen(
    onSubmit: (String) -> Boolean, // returns false if the text was not recognised
    onBack: () -> Unit,
) {
    var text by remember { mutableStateOf("") }
    var invalid by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Header(title = stringResource(R.string.paste_title), onBack = onBack)
        Column(modifier = Modifier.padding(16.dp)) {
            EinkTextField(
                value = text,
                onValueChange = { text = it; invalid = false },
                label = stringResource(R.string.paste_hint),
                singleLine = false,
            )
            if (invalid) {
                Spacer(Modifier.height(8.dp))
                TextMMD(text = stringResource(R.string.paste_invalid), fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(16.dp))
            MmdButton(
                text = stringResource(R.string.paste_button),
                modifier = Modifier.fillMaxWidth(),
                enabled = text.isNotBlank(),
                onClick = { invalid = !onSubmit(text) },
            )
        }
    }
}

/** Manual account entry. */
@Composable
fun ManualEntryScreen(
    onSave: (OtpAccount) -> Unit,
    onBack: () -> Unit,
) {
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var algorithm by remember { mutableStateOf(OtpAlgorithm.SHA1) }
    var digits by remember { mutableStateOf(6) }
    var period by remember { mutableStateOf("30") }
    var type by remember { mutableStateOf(OtpType.TOTP) }

    val secretValid = Base32.isValid(secret)
    val canSave = secretValid && (issuer.isNotBlank() || account.isNotBlank())

    Column(modifier = Modifier.fillMaxSize()) {
        Header(title = stringResource(R.string.manual_title), onBack = onBack)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            EinkTextField(issuer, { issuer = it }, stringResource(R.string.field_issuer))
            EinkTextField(account, { account = it }, stringResource(R.string.field_account))
            EinkTextField(secret, { secret = it.uppercase() }, stringResource(R.string.field_secret))
            if (secret.isNotBlank() && !secretValid) {
                TextMMD(text = stringResource(R.string.manual_invalid_secret), fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }

            FieldLabel(stringResource(R.string.field_type))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SegmentButton(stringResource(R.string.type_totp), type == OtpType.TOTP, Modifier.weight(1f)) { type = OtpType.TOTP }
                SegmentButton(stringResource(R.string.type_hotp), type == OtpType.HOTP, Modifier.weight(1f)) { type = OtpType.HOTP }
            }

            FieldLabel(stringResource(R.string.field_algorithm))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SegmentButton("SHA1", algorithm == OtpAlgorithm.SHA1, Modifier.weight(1f)) { algorithm = OtpAlgorithm.SHA1 }
                SegmentButton("SHA256", algorithm == OtpAlgorithm.SHA256, Modifier.weight(1f)) { algorithm = OtpAlgorithm.SHA256 }
                SegmentButton("SHA512", algorithm == OtpAlgorithm.SHA512, Modifier.weight(1f)) { algorithm = OtpAlgorithm.SHA512 }
            }

            FieldLabel(stringResource(R.string.field_digits))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SegmentButton("6", digits == 6, Modifier.weight(1f)) { digits = 6 }
                SegmentButton("8", digits == 8, Modifier.weight(1f)) { digits = 8 }
            }

            if (type == OtpType.TOTP) {
                EinkTextField(period, { period = it.filter { c -> c.isDigit() } }, stringResource(R.string.field_period), keyboardType = KeyboardType.Number)
            }

            Spacer(Modifier.height(8.dp))
            MmdButton(
                text = stringResource(R.string.save),
                modifier = Modifier.fillMaxWidth(),
                enabled = canSave,
                onClick = {
                    onSave(
                        OtpAccount(
                            issuer = issuer.trim(),
                            name = account.trim(),
                            secret = secret.replace(" ", "").uppercase(),
                            algorithm = algorithm,
                            digits = digits,
                            period = period.toIntOrNull()?.takeIf { it > 0 } ?: 30,
                            type = type,
                            counter = 0,
                        )
                    )
                },
            )
        }
    }
}

@Composable
private fun FieldLabel(text: String) {
    TextMMD(text = text, fontSize = 13.sp, fontWeight = FontWeight.Bold)
}
