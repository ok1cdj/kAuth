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

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.mudita.mmd.components.buttons.ButtonMMD
import com.mudita.mmd.components.text.TextMMD

/**
 * The one e-ink push-button used everywhere: a [ButtonMMD] with a 1px black
 * outline (grey when disabled), an 8dp corner and a centred bold label. One
 * definition so the whole app restyles from a single place.
 */
@Composable
fun MmdButton(
    text: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    fontSize: TextUnit = 15.sp,
    onClick: () -> Unit,
) {
    ButtonMMD(
        onClick = { if (enabled) onClick() },
        modifier = modifier
            .height(56.dp)
            .border(1.dp, if (enabled) Color.Black else Color.Gray, RoundedCornerShape(8.dp)),
        shape = RoundedCornerShape(8.dp),
    ) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            TextMMD(text = text, fontSize = fontSize, fontWeight = FontWeight.Bold)
        }
    }
}

/**
 * The shared modal chrome: a centred white card with a 1px black border, 12dp
 * corners and 16dp padding. [modifier] lets a caller bound the height (e.g. the
 * scrolling About card). Content is laid out in the card's [ColumnScope].
 */
@Composable
fun MmdDialog(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .then(modifier)
                .border(1.dp, Color.Black, RoundedCornerShape(12.dp))
                .background(Color.White, RoundedCornerShape(12.dp))
                .padding(16.dp),
            content = content,
        )
    }
}

/**
 * A bordered single-line text field styled for e-ink (black outline/text/cursor,
 * white fill, no Material tint). Used for every input in the app.
 */
@Composable
fun EinkTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    isPassword: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Text,
    singleLine: Boolean = true,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { TextMMD(text = label, fontSize = 13.sp) },
        singleLine = singleLine,
        modifier = modifier.fillMaxWidth(),
        textStyle = TextStyle(color = Color.Black, fontSize = 16.sp),
        visualTransformation = if (isPassword) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(
            keyboardType = if (isPassword) KeyboardType.Password else keyboardType,
        ),
        shape = RoundedCornerShape(8.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Color.Black,
            unfocusedBorderColor = Color.Black,
            focusedTextColor = Color.Black,
            unfocusedTextColor = Color.Black,
            cursorColor = Color.Black,
            focusedLabelColor = Color.Black,
            unfocusedLabelColor = Color.Black,
            focusedContainerColor = Color.White,
            unfocusedContainerColor = Color.White,
        ),
    )
}

/**
 * One option of a multi-way choice; the active one is inverted (black fill, white
 * label). A plain [Box] rather than [ButtonMMD], because MMD paints its own white
 * surface which would hide the black fill.
 */
@Composable
fun SegmentButton(text: String, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(8.dp)
    Box(
        modifier = modifier
            .height(48.dp)
            .background(if (selected) Color.Black else Color.White, shape)
            .border(1.dp, Color.Black, shape)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        TextMMD(
            text = text,
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = if (selected) Color.White else Color.Black,
        )
    }
}

/**
 * The large monospace OTP code. A plain [Text] (not [TextMMD]) so we can force a
 * monospace family — the spec calls for a big monospace code, grouped as "123 456"
 * for readability.
 */
@Composable
fun MonoCode(code: String, modifier: Modifier = Modifier, fontSize: TextUnit = 34.sp) {
    Text(
        text = grouped(code),
        color = Color.Black,
        fontSize = fontSize,
        fontWeight = FontWeight.Bold,
        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
        modifier = modifier,
    )
}

private fun grouped(code: String): String = when (code.length) {
    6 -> "${code.substring(0, 3)} ${code.substring(3)}"
    8 -> "${code.substring(0, 4)} ${code.substring(4)}"
    else -> code
}
