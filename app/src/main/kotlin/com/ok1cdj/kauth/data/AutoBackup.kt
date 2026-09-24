/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.ok1cdj.kauth.data

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Writes the encrypted vault blob into a user-chosen SAF folder, replacing the
 * single previous backup. The blob is the same password-wrapped format as a
 * manual export, so the file restores through the normal Restore flow.
 *
 * SAF can't rename over an existing document (the external-storage provider
 * would pick "name (1)" instead), so the replace is: write + verify a `.tmp`,
 * delete the old file, rename the `.tmp`. The rule throughout: an existing
 * backup is only deleted after a newer one has been written and read back.
 * An interrupted run can leave just a valid `.tmp`; the next run promotes it to
 * the real name before doing anything else.
 *
 * Providers that can't rename (some cloud ones) get an in-place overwrite
 * instead — not atomic, but it never deletes the only copy.
 */
class AutoBackup(private val context: Context) {

    /** Returns false (never throws) if the folder is gone or access was revoked. */
    suspend fun write(treeUri: Uri, blob: String): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val dir = DocumentFile.fromTreeUri(context, treeUri) ?: return@runCatching false
            if (!dir.canWrite()) return@runCatching false
            val bytes = blob.toByteArray(Charsets.UTF_8)

            var target = dir.findFile(FILE_NAME)
            var leftover = dir.findFile(TMP_NAME)

            // A previous run died between deleting the old file and the rename:
            // the `.tmp` is the only good copy, so promote it first.
            if (target == null && leftover != null && supportsRename(leftover.uri)) {
                if (leftover.renameTo(FILE_NAME) && leftover.name == FILE_NAME) {
                    target = leftover
                    leftover = null
                }
            }

            if (target == null) {
                // Nothing to replace. Keep an unpromotable leftover until the new
                // file is verified.
                val fresh = dir.createFile(MIME, FILE_NAME) ?: return@runCatching false
                val ok = writeVerified(fresh.uri, bytes)
                if (ok) leftover?.delete()
                return@runCatching ok && fresh.name == FILE_NAME
            }

            if (!supportsRename(target.uri)) return@runCatching writeVerified(target.uri, bytes)

            // `target` is a complete backup, so a leftover `.tmp` beside it is junk.
            leftover?.delete()
            val tmp = dir.createFile(MIME, TMP_NAME) ?: return@runCatching false
            if (!writeVerified(tmp.uri, bytes)) {
                tmp.delete()
                return@runCatching false
            }
            if (!target.delete()) {
                tmp.delete()
                return@runCatching false
            }
            // If this rename fails the verified `.tmp` stays and is promoted next time.
            tmp.renameTo(FILE_NAME) && tmp.name == FILE_NAME
        }.getOrDefault(false)
    }

    /** Write [bytes] to [uri] (truncating), then read it back and compare. */
    private fun writeVerified(uri: Uri, bytes: ByteArray): Boolean {
        context.contentResolver.openOutputStream(uri, "wt")?.use {
            it.write(bytes)
            it.flush()
        } ?: return false
        val readBack = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        return readBack != null && readBack.contentEquals(bytes)
    }

    private fun supportsRename(uri: Uri): Boolean =
        context.contentResolver.query(uri, arrayOf(DocumentsContract.Document.COLUMN_FLAGS), null, null, null)
            ?.use { c -> c.moveToFirst() && (c.getInt(0) and DocumentsContract.Document.FLAG_SUPPORTS_RENAME) != 0 }
            ?: false

    /** Human-readable name of the chosen folder, for the settings row. */
    fun folderName(treeUri: Uri): String? =
        runCatching { DocumentFile.fromTreeUri(context, treeUri)?.name }.getOrNull()

    companion object {
        const val FILE_NAME = "kauth-autobackup.kauth"
        private const val TMP_NAME = "$FILE_NAME.tmp"
        private const val MIME = "application/octet-stream"
    }
}
