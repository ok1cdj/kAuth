# kAuth keeps default AGP/R8 rules. Compose, CameraX and MMD ship their own
# consumer ProGuard rules. The :core module is plain Kotlin with no reflection.
#
# ZXing's core reflects over optional format readers; keep it so QR decoding
# survives shrinking.
-keep class com.google.zxing.** { *; }
-dontwarn com.google.zxing.**

# BouncyCastle (Argon2id) — keep the provider classes we call into.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
