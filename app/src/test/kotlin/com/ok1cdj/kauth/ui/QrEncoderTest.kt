/*
 * kAuth — TOTP/HOTP authenticator for the Mudita Kompakt
 * Copyright (C) 2026 Ondrej Kolonicny (OK1CDJ)
 */

package com.ok1cdj.kauth.ui

import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.ok1cdj.kauth.core.OtpAccount
import com.ok1cdj.kauth.core.OtpType
import com.ok1cdj.kauth.core.OtpUri
import org.junit.Assert.assertEquals
import org.junit.Test

class QrEncoderTest {

    /** Render the module matrix at [scale] px per module and decode it back. */
    private fun roundTrip(text: String, scale: Int = 4): String {
        val m = QrEncoder.encode(text)
        val w = m.width * scale
        val px = IntArray(w * w) { i ->
            if (m[(i % w) / scale, (i / w) / scale]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
        }
        return MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(w, w, px)))).text
    }

    @Test
    fun `totp uri survives encode and decode`() {
        val uri = OtpUri.build(OtpAccount(issuer = "Příklad s.r.o.", name = "jana@example.com", secret = "JBSWY3DPEHPK3PXP"))
        assertEquals(uri, roundTrip(uri))
    }

    @Test
    fun `hotp uri with long secret survives encode and decode`() {
        val acc = OtpAccount(issuer = "ACME", name = "bob", secret = "JBSWY3DPEHPK3PXP".repeat(4), type = OtpType.HOTP, counter = 42)
        val uri = OtpUri.build(acc)
        assertEquals(uri, roundTrip(uri))
    }
}
