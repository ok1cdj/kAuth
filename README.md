# kAuth

A minimal **TOTP/HOTP two-factor authenticator** for the [Mudita Kompakt](https://mudita.com/),
part of the `k*` family of e-ink-first apps. It generates the usual 6/8-digit
one-time codes, imports accounts from Google Authenticator, and keeps every
secret in a vault encrypted with a master password.

kAuth is designed for e-ink: a forced light theme, no animations, sharp borders
instead of shadows, large monospace codes, and a plain numeric countdown instead
of an animated ring.

## Features

- **RFC 6238 (TOTP) and RFC 4226 (HOTP)** with HMAC-SHA1/SHA256/SHA512,
  configurable digits (6/8) and period. The whole OTP engine lives in a pure-JVM
  `:core` module tested against the official RFC test vectors.
- **Three ways to add an account:**
  - Manual entry (issuer, account, Base32 secret, algorithm, digits, period).
  - `otpauth://` URI — pasted as text or scanned.
  - QR scan with a **single camera snapshot** (no continuous viewfinder — that
    would ghost the e-ink panel), decoded with ZXing.
- **Robust Google Authenticator import** (`otpauth-migration://`). The migration
  payload is decoded from scratch per the public field specification. A malformed
  account in a batch is reported and skipped — it never crashes the import.
  Multi-part exports (Google splits large exports across several QR codes) are
  scanned part by part and summarised at the end (added / failed).
- **Password-encrypted vault.** Secrets are encrypted with AES-256-GCM; the key
  is derived from your master password with **Argon2id**. The password is asked
  on every launch and is never stored.
- **Encrypted backup.** Export the whole vault to a single encrypted file
  (same Argon2id / AES-256-GCM as the live vault) and restore it later. This is
  the only backup mechanism — there is no cloud sync.
- **Screenshot / screen-capture prevention** on the codes screen (`FLAG_SECURE`).
- English and Czech localisation, following the device language.

## Security model

- The master password is the **only** key to your secrets. kAuth uses envelope
  encryption: a random **vault master key (VMK)** encrypts the account data with
  AES-256-GCM, and the VMK itself is wrapped by a key derived from your password
  with Argon2id (per-vault random salt, parameters stored alongside the vault).
- **There is no password recovery.** If you forget the master password, the vault
  cannot be decrypted — by anyone, including you. Keep an encrypted backup and
  remember the password.
- The plaintext password and decrypted secrets exist only in memory while the app
  is unlocked; they are never written to disk in the clear.
- The vault key layering means a future biometric unlock (planned for v2) can wrap
  the same VMK with an Android Keystore key **without re-encrypting or migrating**
  the vault format.

Standard 2FA-app trade-off: strong encryption with no recovery. You are
responsible for remembering the password and keeping a backup.

## Architecture

```
kAuth/
├── core/   Pure Kotlin/JVM — no Android. Unit-tested without an emulator.
│           Base32, HOTP/TOTP, otpauth:// parsing, otpauth-migration decoding,
│           the vault crypto (Argon2id + AES-256-GCM) and password strength.
└── app/    Jetpack Compose UI + MMD (Mudita Mindful Design) e-ink components.
            Preferences DataStore for the encrypted vault blob, CameraX for the
            one-shot QR capture, SAF for encrypted backup export/restore.
```

The split keeps all the security- and correctness-critical logic in a module that
runs as plain `./gradlew :core:test` — no device, no Robolectric.

## Build & install

Requires JDK 17+ and the Android SDK (compileSdk 37).

```bash
# Debug build
./gradlew assembleDebug

# Run the core test suite (RFC vectors, migration decoding, vault round-trip)
./gradlew :core:test
```

### Release signing

Release builds are signed with a keystore referenced from `local.properties`
(gitignored). Copy the template and fill it in:

```bash
cp local.properties.example local.properties
# then set signing.storeFile / storePassword / keyAlias / keyPassword
```

Generate a keystore once with `keytool` and reuse it for every build (changing it
breaks app updates). Then:

```bash
scripts/build-release.sh   # produces kauth-<versionName>.apk
```

### Release workflow (CI)

Pushing a `v*` tag builds a signed APK in GitHub Actions and attaches it to a
GitHub Release. Configure these repository secrets:

- `KEYSTORE_BASE64` — `base64 -w0 keystore/kauth.jks`
- `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`

```bash
git tag v1.0 && git push origin v1.0
```

## Out of scope (permanently)

Cloud sync; importing from other authenticators' on-device databases (root). The
only ways to get accounts in are QR/URI import and restoring your own encrypted
backup.

## License

GPL-3.0. See [LICENSE](LICENSE) and the in-app About dialog.
