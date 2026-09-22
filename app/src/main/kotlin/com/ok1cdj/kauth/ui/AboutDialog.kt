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

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.BuildConfig
import com.ok1cdj.kauth.R

private const val GITHUB_URL = "https://github.com/ok1cdj/kAuth"

@Composable
fun AboutDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    MmdDialog(onDismiss = onDismiss, modifier = Modifier.heightIn(max = 560.dp)) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState()),
        ) {
            TextMMD(text = stringResource(R.string.about_title), fontSize = 22.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(2.dp))
            TextMMD(text = stringResource(R.string.about_version, BuildConfig.VERSION_NAME), fontSize = 13.sp)
            TextMMD(text = stringResource(R.string.about_author), fontSize = 13.sp)
            Spacer(Modifier.height(10.dp))
            TextMMD(text = stringResource(R.string.about_desc), fontSize = 13.sp)
            Spacer(Modifier.height(10.dp))
            TextMMD(text = stringResource(R.string.about_security_title), fontSize = 13.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            TextMMD(text = stringResource(R.string.about_security), fontSize = 12.sp)
            Spacer(Modifier.height(10.dp))
            TextMMD(text = stringResource(R.string.about_license), fontSize = 13.sp, fontWeight = FontWeight.Bold)
        }

        Spacer(Modifier.height(12.dp))
        MmdButton(stringResource(R.string.about_github), modifier = Modifier.fillMaxWidth()) { openUrl(context, GITHUB_URL) }
        Spacer(Modifier.height(8.dp))
        MmdButton(stringResource(R.string.close), modifier = Modifier.fillMaxWidth(), onClick = onDismiss)
    }
}

private fun openUrl(context: Context, url: String) {
    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
}
