package io.linscp.commander

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore plugin – wraps the 32-byte `sessions.key` master key with
 * a hardware-backed AES-256-GCM key stored in `AndroidKeyStore`.
 *
 * Storage format on disk (Rust-compatible): `aks1$<base64(wrapped)>`
 * where wrapped = `iv (12 bytes) || ciphertext || tag`.
 * When the user enables biometric lock, `setUserAuthenticationRequired(true)`
 * is set on the key and `authenticateIfNeeded` prompts `BiometricPrompt`
 * before any Rust `load_or_create_master_key` can unwrap.
 */
class LinScpKeystorePlugin(private val context: Context) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "LinSCP-master-key-v1"
        private const val PREFS_FILE = "linscp_keystore_prefs"
        private const val PREF_BIOMETRIC = "keystore_biometric_required"
        private const val GCM_IV_LEN = 12
        private const val GCM_TAG_LEN = 128

        fun configDir(context: Context): java.io.File =
            java.io.File(context.filesDir, "config").also { it.mkdirs() }

        fun shouldRequireBiometric(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
            if (!prefs.getBoolean(PREF_BIOMETRIC, false)) return false
            return BiometricManager.from(context)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
        }

        fun setBiometricRequired(context: Context, required: Boolean) {
            context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
                .edit().putBoolean(PREF_BIOMETRIC, required).apply()
            // Force regeneration so KeyGenParameterSpec picks up new auth flag
            if (!required) return
            try {
                val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                ks.deleteEntry(KEY_ALIAS)
            } catch (_: Exception) {}
        }
    }

    private fun getOrCreateSecretKey(requireAuth: Boolean): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        ks.getKey(KEY_ALIAS, null)?.let { return it as SecretKey }

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }
        if (requireAuth) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
        }
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGen.init(builder.build())
        return keyGen.generateKey()
    }

    fun wrapMasterKey(rawKey: ByteArray): ByteArray {
        require(rawKey.size == 32) { "master key must be 32 bytes" }
        val requireAuth = shouldRequireBiometric(context)
        val secretKey = getOrCreateSecretKey(requireAuth)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv // 12 bytes
        require(iv.size == GCM_IV_LEN)
        val ciphertext = cipher.doFinal(rawKey)
        return iv + ciphertext
    }

    fun unwrapMasterKey(wrapped: ByteArray): ByteArray {
        require(wrapped.size > GCM_IV_LEN) { "wrapped key too short" }
        val requireAuth = shouldRequireBiometric(context)
        val secretKey = getOrCreateSecretKey(requireAuth)
        val iv = wrapped.copyOfRange(0, GCM_IV_LEN)
        val ciphertext = wrapped.copyOfRange(GCM_IV_LEN, wrapped.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LEN, iv))
        val raw = cipher.doFinal(ciphertext)
        require(raw.size == 32) { "unwrapped key must be 32 bytes" }
        return raw
    }

    fun authenticateIfNeeded(
        title: String,
        onSuccess: () -> Unit,
        onFallback: () -> Unit,
    ) {
        if (!shouldRequireBiometric(context)) {
            onSuccess()
            return
        }
        val activity = context as? FragmentActivity ?: run {
            onFallback()
            return
        }
        val executor = ContextCompat.getMainExecutor(context)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onSuccess()
            }
            override fun onAuthenticationFailed() {
                // keep prompt open – user can retry
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                // Fallback to device credential or continue without biometric if user cancels?
                onFallback()
            }
        }
        val prompt = BiometricPrompt(activity, executor, callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle("Authenticate to unlock saved sessions")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()
        prompt.authenticate(promptInfo)
    }

    // Rust bridge helpers – base64-wrapped for storage in sessions.key (aks1$ prefix)

    fun wrapForStorage(rawKey: ByteArray): String {
        val wrapped = wrapMasterKey(rawKey)
        return "aks1\$" + Base64.encodeToString(wrapped, Base64.NO_WRAP)
    }

    fun unwrapFromStorage(stored: String): ByteArray {
        val b64 = stored.removePrefix("aks1\$").trim()
        val wrapped = Base64.decode(b64, Base64.NO_WRAP)
        return unwrapMasterKey(wrapped)
    }
}
