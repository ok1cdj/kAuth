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
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.R
import com.ok1cdj.kauth.core.Otp
import com.ok1cdj.kauth.core.OtpAccount
import com.ok1cdj.kauth.core.OtpType
import kotlinx.coroutines.delay

@Composable
fun AccountsScreen(
    accounts: List<OtpAccount>,
    onAdd: () -> Unit,
    onAbout: () -> Unit,
    onSettings: () -> Unit,
    onDelete: (OtpAccount) -> Unit,
    onAdvanceHotp: (OtpAccount) -> Unit,
) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var actionTarget by remember { mutableStateOf<OtpAccount?>(null) }
    var deleteTarget by remember { mutableStateOf<OtpAccount?>(null) }

    // One shared clock, updated every second. Codes recompute at the period
    // boundary; the countdown number changes each tick — a small area, so the
    // e-ink refresh stays cheap.
    val now by produceState(initialValue = System.currentTimeMillis()) {
        while (true) {
            value = System.currentTimeMillis()
            delay(1000)
        }
    }

    // Search is offered once the list is long enough to warrant it; the toggle
    // reveals a filter field. Filtering is display-only — order and storage are
    // untouched.
    var searchOpen by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    val showSearch = searchOpen || accounts.size > 6
    // Memoized so the 1-second `now` tick (which recomposes this screen to update
    // the countdown) doesn't re-scan the whole list every second.
    val shown = remember(accounts, query) {
        if (query.isBlank()) accounts else accounts.filter {
            it.label().contains(query, ignoreCase = true) ||
                it.issuer.contains(query, ignoreCase = true) ||
                it.name.contains(query, ignoreCase = true)
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Header(
            title = stringResource(R.string.accounts_title),
            actions = {
                if (accounts.isNotEmpty()) SearchButton(onClick = { searchOpen = !searchOpen; if (!searchOpen) query = "" })
                AddButton(onClick = onAdd)
                SettingsButton(onClick = onSettings)
                InfoButton(onClick = onAbout)
            },
        )

        if (showSearch && accounts.isNotEmpty()) {
            EinkTextField(
                value = query,
                onValueChange = { query = it },
                label = stringResource(R.string.search),
                modifier = Modifier.padding(horizontal = 12.dp),
            )
            Spacer(Modifier.height(8.dp))
        }

        when {
            accounts.isEmpty() ->
                Box(modifier = Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                    TextMMD(text = stringResource(R.string.accounts_empty), fontSize = 15.sp)
                }
            shown.isEmpty() ->
                Box(modifier = Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                    TextMMD(text = stringResource(R.string.search_no_match), fontSize = 15.sp)
                }
            else ->
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 8.dp),
                ) {
                    items(shown, key = { it.dedupeKey() }) { account ->
                        AccountRow(
                            account = account,
                            now = now,
                            onClick = { actionTarget = account },
                            onAdvanceHotp = { onAdvanceHotp(account) },
                        )
                    }
                }
        }
    }

    actionTarget?.let { acc ->
        AccountActionsDialog(
            account = acc,
            now = now,
            onCopy = {
                val code = runCatching { Otp.code(acc, now) }.getOrDefault("")
                clipboard.setText(AnnotatedString(code))
                Toast.makeText(context, R.string.code_copied, Toast.LENGTH_SHORT).show()
                actionTarget = null
            },
            onDelete = {
                deleteTarget = acc
                actionTarget = null
            },
            onDismiss = { actionTarget = null },
        )
    }

    deleteTarget?.let { acc ->
        MmdDialog(onDismiss = { deleteTarget = null }) {
            TextMMD(text = stringResource(R.string.delete_title), fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            TextMMD(text = stringResource(R.string.delete_body, acc.label()), fontSize = 13.sp)
            Spacer(Modifier.height(16.dp))
            MmdButton(stringResource(R.string.delete), modifier = Modifier.fillMaxWidth()) {
                onDelete(acc)
                deleteTarget = null
            }
            Spacer(Modifier.height(8.dp))
            MmdButton(stringResource(R.string.cancel), modifier = Modifier.fillMaxWidth()) { deleteTarget = null }
        }
    }
}

@Composable
private fun AccountRow(
    account: OtpAccount,
    now: Long,
    onClick: () -> Unit,
    onAdvanceHotp: () -> Unit,
) {
    val code = remember(account, if (account.type == OtpType.TOTP) now / (account.period * 1000L) else account.counter) {
        runCatching { Otp.code(account, now) }.getOrDefault("------")
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color.Black, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 10.dp),
    ) {
        TextMMD(text = account.label(), fontSize = 13.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            MonoCode(code = code)
            Spacer(Modifier.weight(1f))
            if (account.type == OtpType.TOTP) {
                Countdown(period = account.period, now = now)
            } else {
                MmdButton(
                    text = stringResource(R.string.hotp_next),
                    modifier = Modifier.width(96.dp),
                    fontSize = 13.sp,
                    onClick = onAdvanceHotp,
                )
            }
        }
    }
}

/** A plain numeric + discrete-bar countdown — no animated ring. */
@Composable
private fun Countdown(period: Int, now: Long) {
    val remaining = Otp.secondsRemaining(period, now)
    Column(horizontalAlignment = Alignment.End) {
        TextMMD(text = stringResource(R.string.seconds_left, remaining), fontSize = 15.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        // A short bar that empties in ~5 discrete steps over the period.
        val steps = 5
        val filled = (remaining * steps + period - 1) / period
        Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            for (i in 0 until steps) {
                Box(
                    modifier = Modifier
                        .width(8.dp)
                        .height(8.dp)
                        .border(1.dp, Color.Black)
                        .background(if (i < filled) Color.Black else Color.White),
                )
            }
        }
    }
}

@Composable
private fun AccountActionsDialog(
    account: OtpAccount,
    now: Long,
    onCopy: () -> Unit,
    onDelete: () -> Unit,
    onDismiss: () -> Unit,
) {
    // Key on the period boundary (like AccountRow) so the code isn't re-derived
    // every 1-second tick while the dialog is open.
    val code = remember(account, if (account.type == OtpType.TOTP) now / (account.period * 1000L) else account.counter) {
        runCatching { Otp.code(account, now) }.getOrDefault("------")
    }
    MmdDialog(onDismiss = onDismiss) {
        TextMMD(text = account.label(), fontSize = 16.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(12.dp))
        Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            MonoCode(code = code, fontSize = 40.sp)
        }
        Spacer(Modifier.height(16.dp))
        MmdButton(stringResource(R.string.copy), modifier = Modifier.fillMaxWidth(), onClick = onCopy)
        Spacer(Modifier.height(8.dp))
        MmdButton(stringResource(R.string.delete), modifier = Modifier.fillMaxWidth(), onClick = onDelete)
        Spacer(Modifier.height(8.dp))
        MmdButton(stringResource(R.string.close), modifier = Modifier.fillMaxWidth(), onClick = onDismiss)
    }
}
