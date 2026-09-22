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

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.R
import com.ok1cdj.kauth.core.OtpAccount

/**
 * Reviews a Google Authenticator import in progress. Multi-part exports are
 * accumulated across scans — the user can scan another part, or finish and commit
 * what has been gathered. Failures are shown but never block the rest.
 */
@Composable
fun ImportReviewScreen(
    pending: List<OtpAccount>,
    failures: List<String>,
    batchIndex: Int,
    batchSize: Int,
    onScanMore: () -> Unit,
    onFinish: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Header(title = stringResource(R.string.import_title), onBack = onCancel)
        Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
            if (batchSize > 1) {
                TextMMD(
                    text = stringResource(R.string.import_part, batchIndex + 1, batchSize),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(4.dp))
            }
            TextMMD(
                text = stringResource(R.string.import_progress, pending.size, failures.size),
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(12.dp))

            LazyColumn(
                modifier = Modifier.fillMaxWidth().weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                items(pending, key = { it.dedupeKey() }) { acc ->
                    TextMMD(text = "• ${acc.label()}", fontSize = 13.sp)
                }
                if (failures.isNotEmpty()) {
                    items(failures) { msg ->
                        TextMMD(text = "⚠ $msg", fontSize = 12.sp)
                    }
                }
            }

            Spacer(Modifier.height(12.dp))
            MmdButton(stringResource(R.string.import_scan_more), modifier = Modifier.fillMaxWidth(), onClick = onScanMore)
            Spacer(Modifier.height(8.dp))
            MmdButton(
                text = stringResource(R.string.import_finish),
                modifier = Modifier.fillMaxWidth(),
                enabled = pending.isNotEmpty(),
                onClick = onFinish,
            )
        }
    }
}
