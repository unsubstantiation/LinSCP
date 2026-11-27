# Android biometric vault unlock

On Android 9 or later, when a supported biometric is enrolled, the vault gate
can offer **Enable biometric unlock on this device**. Enter the vault password,
check the option and confirm the system biometric prompt. On later launches,
choose **Unlock with biometrics**. The vault password remains the recovery
method and is not replaced; keep it safe. Use **Disable biometric unlock** on
the vault gate to remove the device's biometric credential.

The opt-in stores an encrypted copy of the vault password in app-private,
no-backup storage. A separate Android Keystore AES-GCM key requires biometric
authentication for each operation and is invalidated when biometric enrollment
changes. Android 11 and later request a strong biometric. Android 9 and 10 use
the platform's biometric CryptoObject path. Availability depends on the device,
Android version and enrolled biometric; Android 8 and devices without a
suitable biometric continue to use the vault password. Cancellation, lockout,
key invalidation, removed biometrics, app-data removal and restored backups can
require the password. To re-enable after an enrollment change, disable the old
biometric credential at the vault gate, then unlock with the password and opt
in again.

The biometric prompt releases a credential to the native service, not to the
WebView. This convenience does not protect an already unlocked app from
malicious code running in its privileged WebView, and Android vendors differ in
biometric hardware and security implementation. This repository currently ships
an Android mobile host; it does not provide an iOS biometric implementation.
