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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ok1cdj.kauth.R

// Header icon sizing — generous touch targets for the Kompakt's e-ink panel,
// where small glyphs are hard to hit reliably.
private val TOUCH_TARGET = 48.dp
private val ICON = 34.dp

@Composable
private fun IconButton(resId: Int, contentDescription: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier.size(TOUCH_TARGET).clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            painter = painterResource(resId),
            contentDescription = contentDescription,
            modifier = Modifier.size(ICON),
        )
    }
}

/** The About (ⓘ) button. */
@Composable
fun InfoButton(onClick: () -> Unit) =
    IconButton(R.drawable.ic_info, stringResource(R.string.about), onClick)

/** The Settings (gear) button. */
@Composable
fun SettingsButton(onClick: () -> Unit) =
    IconButton(R.drawable.ic_settings, stringResource(R.string.settings), onClick)

/** The Add (+) button. */
@Composable
fun AddButton(onClick: () -> Unit) =
    IconButton(R.drawable.ic_add, stringResource(R.string.add), onClick)

/** The Back (‹) button. */
@Composable
fun BackButton(onClick: () -> Unit) =
    IconButton(R.drawable.ic_back, stringResource(R.string.back), onClick)

/** The Search (magnifier) button. */
@Composable
fun SearchButton(onClick: () -> Unit) =
    IconButton(R.drawable.ic_search, stringResource(R.string.search), onClick)
