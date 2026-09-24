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

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** Encodes text as a QR module matrix with ZXing core (the library we decode with). */
object QrEncoder {

    private val hints = mapOf(
        EncodeHintType.MARGIN to 2,
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        EncodeHintType.CHARACTER_SET to "UTF-8",
    )

    /** One entry per module (size 0 requests the minimal matrix, no upscaling). */
    fun encode(text: String): BitMatrix =
        QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints)
}

/** A square black-on-white QR drawn module by module — crisp on e-ink, no bitmap. */
@Composable
fun QrCode(text: String, modifier: Modifier = Modifier) {
    val matrix = remember(text) { QrEncoder.encode(text) }
    Canvas(modifier = modifier.aspectRatio(1f)) {
        drawRect(Color.White)
        val n = matrix.width
        val cell = size.minDimension / n
        for (y in 0 until n) for (x in 0 until n) {
            if (matrix[x, y]) {
                // Round outward by a hair so adjacent modules don't leave hairline gaps.
                drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
            }
        }
    }
}
