package com.example.security

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

data class CtpExportOptions(
    val lockConfig: Boolean = true,
    val expiresAtMillis: Long = 0L,
    val unlockPassword: String = "",
    val requirePasswordOnImport: Boolean = false,
    val lockedHwid: String = "",
    val blockRoot: Boolean = false,
    val creatorMessage: String = ""
)

sealed class CtpDecryptResult {
    data class Success(val profileJson: String) : CtpDecryptResult()
    data class PasswordRequired(val hint: String = "This .ctp configuration is password-protected.") : CtpDecryptResult()
    data class Failure(val reason: String) : CtpDecryptResult()
}

/**
 * Authenticated AES-256-GCM encryption engine for Custom Tunnel Pro (.ctp) files
 * and root-resistant local profile storage.
 */
object CtpConfigCrypto {

    const val CTP_FILE_EXTENSION = "ctp"
    const val CTP_HEADER_PREFIX = "CTP2:"
    const val CTP_URI_PREFIX = "ctp://"
    private const val LOCAL_STORE_PREFIX = "CTP_STORE_V2:"

    private const val PBKDF2_ITERATIONS = 16000
    private const val KEY_LENGTH_BITS = 256
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val SALT_BYTES = 16

    // Multi-part XOR-obfuscated master key shards (no plaintext key string in DEX)
    private val SHARD_A = intArrayOf(
        0x19, 0x2F, 0x29, 0x2E, 0x35, 0x37, 0x0E, 0x2F,
        0x34, 0x34, 0x3F, 0x36, 0x0A, 0x28, 0x35, 0x68
    )
    private val SHARD_B = intArrayOf(
        0x7A, 0x45, 0x52, 0x49, 0x50, 0x4A, 0x6E, 0x71,
        0x4D, 0x58, 0x44, 0x19, 0x62, 0x53, 0x47, 0x1E
    )
    private const val XOR_MASK_A = 0x5A
    private const val XOR_MASK_B = 0x21

    private fun reconstructMasterSecret(): String {
        val sb = StringBuilder(36)
        for (b in SHARD_A) {
            sb.append((b xor XOR_MASK_A).toChar())
        }
        sb.append("::")
        for (b in SHARD_B) {
            sb.append((b xor XOR_MASK_B).toChar())
        }
        return sb.toString()
    }

    fun hashUnlockPassword(password: String): String {
        if (password.isBlank()) return ""
        val salt = ByteArray(8)
        SecureRandom().nextBytes(salt)
        val saltHex = salt.joinToString("") { "%02x".format(it) }
        val hashHex = computeSaltedHash(password, saltHex)
        return "$saltHex:$hashHex"
    }

    fun verifyUnlockPassword(password: String, storedHash: String): Boolean {
        if (storedHash.isBlank()) return false
        val parts = storedHash.split(":")
        if (parts.size != 2) return false
        val expected = computeSaltedHash(password, parts[0])
        return MessageDigest.isEqual(
            expected.toByteArray(StandardCharsets.UTF_8),
            parts[1].toByteArray(StandardCharsets.UTF_8)
        )
    }

    private fun computeSaltedHash(password: String, saltHex: String): String {
        val spec = PBEKeySpec(
            (password + "|" + reconstructMasterSecret()).toCharArray(),
            saltHex.toByteArray(StandardCharsets.UTF_8),
            10000,
            256
        )
        val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val bytes = skf.generateSecret(spec).encoded
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun isCtpContent(rawInput: String): Boolean {
        val trimmed = rawInput.trim()
        return trimmed.startsWith(CTP_HEADER_PREFIX, ignoreCase = true) ||
            trimmed.startsWith(CTP_URI_PREFIX, ignoreCase = true)
    }

    /**
     * Encrypts a VpnProfile JSON representation into an authenticated `.ctp` payload.
     */
    fun encryptProfileJsonToCtp(
        baseProfileJson: String,
        options: CtpExportOptions
    ): String {
        val profileObj = JSONObject(baseProfileJson).apply {
            put("isLocked", options.lockConfig)
            put("expiresAtMillis", options.expiresAtMillis)
            put("lockedHwid", options.lockedHwid.trim().uppercase())
            put("blockRoot", options.blockRoot)
            put("creatorMessage", options.creatorMessage.trim())
            if (options.unlockPassword.isNotBlank()) {
                put("lockPasswordHash", hashUnlockPassword(options.unlockPassword))
            } else {
                put("lockPasswordHash", "")
            }
        }

        val innerCiphertext = if (options.requirePasswordOnImport && options.unlockPassword.isNotBlank()) {
            encryptBytes(
                plaintext = profileObj.toString().toByteArray(StandardCharsets.UTF_8),
                passphrase = "${reconstructMasterSecret()}|PWD:${options.unlockPassword}",
                aad = "CTP2-PWD-PROTECTED".toByteArray(StandardCharsets.UTF_8)
            )
        } else {
            encryptBytes(
                plaintext = profileObj.toString().toByteArray(StandardCharsets.UTF_8),
                passphrase = "${reconstructMasterSecret()}|STD",
                aad = "CTP2-STANDARD".toByteArray(StandardCharsets.UTF_8)
            )
        }

        val envelope = JSONObject().apply {
            put("v", 2)
            put("app", "com.customtunnelpro.vpn")
            put("pwdReq", options.requirePasswordOnImport && options.unlockPassword.isNotBlank())
            put("rootBlock", options.blockRoot)
            put("exp", options.expiresAtMillis)
            put("hwid", options.lockedHwid.trim().uppercase())
            put("note", options.creatorMessage.trim())
            put("data", Base64.encodeToString(innerCiphertext, Base64.NO_WRAP))
        }

        val outerCipher = encryptBytes(
            plaintext = envelope.toString().toByteArray(StandardCharsets.UTF_8),
            passphrase = "${reconstructMasterSecret()}|ENVELOPE",
            aad = "CTP2-ENVELOPE-AUTH".toByteArray(StandardCharsets.UTF_8)
        )

        return CTP_HEADER_PREFIX + Base64.encodeToString(outerCipher, Base64.NO_WRAP)
    }

    /**
     * Decrypts and validates a `.ctp` configuration string, enforcing root, HWID, expiry, and password locks.
     */
    fun decryptCtpToProfileJson(
        rawCtp: String,
        unlockPassword: String = "",
        context: Context? = null
    ): CtpDecryptResult {
        val cleaned = rawCtp.trim()
            .removePrefix(CTP_HEADER_PREFIX)
            .removePrefix(CTP_HEADER_PREFIX.lowercase())
            .removePrefix(CTP_URI_PREFIX)
            .removePrefix(CTP_URI_PREFIX. uppercase())
            .trim()

        if (cleaned.isEmpty()) {
            return CtpDecryptResult.Failure("Empty .ctp configuration file")
        }

        return try {
            val outerBytes = Base64.decode(cleaned, Base64.DEFAULT)
            val envelopeBytes = decryptBytes(
                packed = outerBytes,
                passphrase = "${reconstructMasterSecret()}|ENVELOPE",
                aad = "CTP2-ENVELOPE-AUTH".toByteArray(StandardCharsets.UTF_8)
            )
            val envelope = JSONObject(String(envelopeBytes, StandardCharsets.UTF_8))
            if (envelope.optInt("v", 0) != 2 || envelope.optString("app") != "com.customtunnelpro.vpn") {
                return CtpDecryptResult.Failure("Invalid or tampered .ctp container signature")
            }

            // 1. Check root lock
            val rootBlock = envelope.optBoolean("rootBlock", false)
            if (rootBlock && DeviceSecurityManager.isDeviceRooted(context)) {
                return CtpDecryptResult.Failure("Security Lock: This .ctp config is blocked on rooted devices")
            }

            // 2. Check expiration lock
            val expiresAt = envelope.optLong("exp", 0L)
            if (expiresAt > 0L && System.currentTimeMillis() > expiresAt) {
                return CtpDecryptResult.Failure("Security Lock: This .ctp configuration has expired")
            }

            // 3. Check Hardware ID lock
            val lockedHwid = envelope.optString("hwid", "").trim()
            if (lockedHwid.isNotBlank() && context != null) {
                val currentHwid = DeviceSecurityManager.getHardwareId(context)
                if (!lockedHwid.equals(currentHwid, ignoreCase = true)) {
                    return CtpDecryptResult.Failure("Security Lock: This .ctp file is locked to another Hardware ID (Your HWID: $currentHwid)")
                }
            }

            // 4. Check password requirement
            val pwdReq = envelope.optBoolean("pwdReq", false)
            if (pwdReq && unlockPassword.isBlank()) {
                return CtpDecryptResult.PasswordRequired("Enter the password to unlock and import this .ctp configuration")
            }

            val innerBytes = Base64.decode(envelope.getString("data"), Base64.DEFAULT)
            val decryptedProfileBytes = try {
                if (pwdReq) {
                    decryptBytes(
                        packed = innerBytes,
                        passphrase = "${reconstructMasterSecret()}|PWD:$unlockPassword",
                        aad = "CTP2-PWD-PROTECTED".toByteArray(StandardCharsets.UTF_8)
                    )
                } else {
                    decryptBytes(
                        packed = innerBytes,
                        passphrase = "${reconstructMasterSecret()}|STD",
                        aad = "CTP2-STANDARD".toByteArray(StandardCharsets.UTF_8)
                    )
                }
            } catch (e: Exception) {
                if (pwdReq) {
                    return CtpDecryptResult.Failure("Incorrect unlock password for .ctp configuration")
                }
                throw e
            }

            CtpDecryptResult.Success(String(decryptedProfileBytes, StandardCharsets.UTF_8))
        } catch (e: Exception) {
            CtpDecryptResult.Failure("Tampered or corrupted .ctp configuration file")
        }
    }

    /**
     * Encrypts local `vpn_profiles.json` storage so rooted users inspecting `/data/data/...` cannot read plaintext profiles.
     */
    fun encryptLocalStore(plainJson: String, context: Context): String {
        val deviceKey = "${reconstructMasterSecret()}|LOCAL_STORE|${DeviceSecurityManager.getHardwareId(context)}"
        val cipherBytes = encryptBytes(
            plaintext = plainJson.toByteArray(StandardCharsets.UTF_8),
            passphrase = deviceKey,
            aad = "CTP-LOCAL-STORE-V2".toByteArray(StandardCharsets.UTF_8)
        )
        return LOCAL_STORE_PREFIX + Base64.encodeToString(cipherBytes, Base64.NO_WRAP)
    }

    /**
     * Decrypts local `vpn_profiles.json` storage, transparently migrating legacy plaintext JSON if needed.
     */
    fun decryptLocalStore(storedContent: String, context: Context): String {
        val trimmed = storedContent.trim()
        if (!trimmed.startsWith(LOCAL_STORE_PREFIX)) {
            // Legacy plaintext JSON array -> return as-is so caller can re-save encrypted
            return trimmed
        }
        val base64Part = trimmed.removePrefix(LOCAL_STORE_PREFIX).trim()
        val packed = Base64.decode(base64Part, Base64.DEFAULT)
        val deviceKey = "${reconstructMasterSecret()}|LOCAL_STORE|${DeviceSecurityManager.getHardwareId(context)}"
        val plainBytes = decryptBytes(
            packed = packed,
            passphrase = deviceKey,
            aad = "CTP-LOCAL-STORE-V2".toByteArray(StandardCharsets.UTF_8)
        )
        return String(plainBytes, StandardCharsets.UTF_8)
    }

    private fun deriveAesKey(passphrase: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val raw = factory.generateSecret(spec).encoded
        return SecretKeySpec(raw, "AES")
    }

    private fun encryptBytes(plaintext: ByteArray, passphrase: String, aad: ByteArray): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(SALT_BYTES)
        val iv = ByteArray(GCM_IV_BYTES)
        random.nextBytes(salt)
        random.nextBytes(iv)

        val key = deriveAesKey(passphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        val cipherText = cipher.doFinal(plaintext)

        // Pack [salt (16B) | iv (12B) | cipherText+tag]
        val packed = ByteArray(SALT_BYTES + GCM_IV_BYTES + cipherText.size)
        System.arraycopy(salt, 0, packed, 0, SALT_BYTES)
        System.arraycopy(iv, 0, packed, SALT_BYTES, GCM_IV_BYTES)
        System.arraycopy(cipherText, 0, packed, SALT_BYTES + GCM_IV_BYTES, cipherText.size)
        return packed
    }

    private fun decryptBytes(packed: ByteArray, passphrase: String, aad: ByteArray): ByteArray {
        require(packed.size > SALT_BYTES + GCM_IV_BYTES + 16) { "Ciphertext too short" }
        val salt = packed.copyOfRange(0, SALT_BYTES)
        val iv = packed.copyOfRange(SALT_BYTES, SALT_BYTES + GCM_IV_BYTES)
        val cipherText = packed.copyOfRange(SALT_BYTES + GCM_IV_BYTES, packed.size)

        val key = deriveAesKey(passphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(cipherText)
    }
}
