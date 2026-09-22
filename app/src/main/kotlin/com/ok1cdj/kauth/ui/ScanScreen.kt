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

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.mudita.mmd.components.text.TextMMD
import com.ok1cdj.kauth.R

/**
 * One-shot QR capture. A preview is shown so the user can aim, but nothing is
 * decoded until they tap Capture — there is no continuous frame-by-frame scan,
 * which on e-ink would ghost and thrash the panel. A single frame is taken,
 * decoded, and handed to [onResult].
 */
@Composable
fun ScanScreen(
    onResult: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> hasPermission = granted }

    var errorRes by remember { mutableStateOf<Int?>(null) }
    var capturing by remember { mutableStateOf(false) }

    val previewView = remember { PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER } }
    val imageCapture = remember {
        ImageCapture.Builder().setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY).build()
    }

    // Bind the camera once permission is granted.
    androidx.compose.runtime.LaunchedEffect(hasPermission) {
        if (!hasPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
            return@LaunchedEffect
        }
        val provider = ProcessCameraProvider.getInstance(context).get()
        val preview = Preview.Builder().build().also { it.surfaceProvider = previewView.surfaceProvider }
        runCatching {
            provider.unbindAll()
            provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, imageCapture)
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Header(title = stringResource(R.string.scan_title), onBack = onBack)

        if (!hasPermission) {
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                TextMMD(text = stringResource(R.string.scan_permission_needed), fontSize = 14.sp)
                Spacer(Modifier.height(16.dp))
                MmdButton(stringResource(R.string.scan_grant), modifier = Modifier.fillMaxWidth()) {
                    permissionLauncher.launch(Manifest.permission.CAMERA)
                }
            }
        } else {
            AndroidView(
                factory = { previewView },
                modifier = Modifier.fillMaxWidth().weight(1f).padding(horizontal = 8.dp),
            )
            Column(modifier = Modifier.padding(16.dp)) {
                TextMMD(text = stringResource(R.string.scan_instructions), fontSize = 13.sp)
                errorRes?.let {
                    Spacer(Modifier.height(6.dp))
                    TextMMD(text = stringResource(it), fontSize = 13.sp)
                }
                Spacer(Modifier.height(12.dp))
                MmdButton(
                    text = stringResource(R.string.scan_capture),
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !capturing,
                    onClick = {
                        capturing = true
                        errorRes = null
                        imageCapture.takePicture(
                            ContextCompat.getMainExecutor(context),
                            object : ImageCapture.OnImageCapturedCallback() {
                                override fun onCaptureSuccess(image: ImageProxy) {
                                    val bitmap = image.toUprightBitmap()
                                    image.close()
                                    capturing = false
                                    val text = bitmap?.let { QrDecoder.decode(it) }
                                    if (text == null) errorRes = R.string.scan_no_qr else onResult(text)
                                }

                                override fun onError(exception: ImageCaptureException) {
                                    capturing = false
                                    errorRes = R.string.scan_no_qr
                                }
                            },
                        )
                    },
                )
            }
        }
    }
}

/** Decode the captured JPEG frame to a Bitmap, rotated upright per its EXIF/sensor. */
private fun ImageProxy.toUprightBitmap(): Bitmap? {
    val buffer = planes.firstOrNull()?.buffer ?: return null
    val bytes = ByteArray(buffer.remaining()).also { buffer.get(it) }
    val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: return null
    val rotation = imageInfo.rotationDegrees
    if (rotation == 0) return bitmap
    val matrix = Matrix().apply { postRotate(rotation.toFloat()) }
    return Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
}
