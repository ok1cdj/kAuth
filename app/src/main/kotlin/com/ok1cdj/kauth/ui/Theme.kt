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

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val black = Color(0xFF000000)
private val white = Color(0xFFFFFFFF)

// Strictly black/white for e-ink; MMD components read MaterialTheme.colorScheme,
// so every role (including the *Container roles used by ButtonMMD) is coerced to
// black/white — otherwise the Material purple baseline leaks through. There is no
// dark theme: large black fills refresh slowly and ghost on e-ink.
private val EinkColors = lightColorScheme(
    primary = black,
    onPrimary = white,
    primaryContainer = white,
    onPrimaryContainer = black,
    secondary = black,
    onSecondary = white,
    secondaryContainer = white,
    onSecondaryContainer = black,
    tertiary = black,
    onTertiary = white,
    tertiaryContainer = white,
    onTertiaryContainer = black,
    background = white,
    onBackground = black,
    surface = white,
    onSurface = black,
    surfaceVariant = white,
    onSurfaceVariant = black,
    outline = black,
    outlineVariant = black,
    error = black,
    onError = white,
)

@Composable
fun KAuthTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = EinkColors, content = content)
}
