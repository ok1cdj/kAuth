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

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer

/**
 * Decodes a QR code from a still [Bitmap] with ZXing core (no camera library, no
 * GMS). Used on the single captured frame — there is no continuous scan loop, so
 * the e-ink panel never has to render a live viewfinder decode.
 */
object QrDecoder {

    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )

    /** Return the decoded text, or null if no QR code is found. */
    fun decode(bitmap: Bitmap): String? {
        val width = bitmap.width
        val height = bitmap.height
        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
        val source = RGBLuminanceSource(width, height, pixels)

        // Two binarizers: Hybrid handles uneven lighting; the global histogram is a
        // cheap fallback for the crisp, high-contrast codes a phone screen shows.
        return tryDecode(BinaryBitmap(HybridBinarizer(source)))
            ?: tryDecode(BinaryBitmap(GlobalHistogramBinarizer(source)))
    }

    private fun tryDecode(bmp: BinaryBitmap): String? =
        runCatching { MultiFormatReader().apply { setHints(hints) }.decodeWithState(bmp).text }.getOrNull()
}
