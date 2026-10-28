package com.example.security

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.security.MessageDigest
import java.util.Locale

/**
 * Provides Hardware ID (HWID) generation, root detection, anti-tamper package verification,
 * and runtime debugger/hook checks for Custom Tunnel Pro (.ctp) security locks.
 */
object DeviceSecurityManager {

    private val SU_PATHS = arrayOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/sbin/magisk",
        "/system/bin/magisk",
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/data/adb/ap"
    )

    private val ROOT_PACKAGES = arrayOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "me.weishu.kernelsu",
        "me.bmax.apatch"
    )

    /**
     * Generates a stable, privacy-safe 16-character uppercase Hardware ID (HWID)
     * specific to this device so users can copy and share it with config creators.
     */
    @SuppressLint("HardwareIds")
    fun getHardwareId(context: Context): String {
        val androidId = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: ""
        } catch (e: Exception) {
            ""
        }
        val rawFingerprint = buildString {
            append(androidId.ifBlank { "CTP_FALLBACK_ID" })
            append("|")
            append(Build.BOARD)
            append("|")
            append(Build.BRAND)
            append("|")
            append(Build.DEVICE)
            append("|")
            append(Build.HARDWARE)
            append("|")
            append(Build.MANUFACTURER)
            append("|")
            append(Build.MODEL)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(rawFingerprint.toByteArray(Charsets.UTF_8))
        val hex = digest.joinToString("") { "%02X".format(it) }
        // Format as CTP-XXXX-XXXX-XXXX
        return "CTP-${hex.substring(0, 4)}-${hex.substring(4, 8)}-${hex.substring(8, 12)}"
    }

    /**
     * Checks if the device is rooted (su binary, Magisk/KernelSU/APatch artifacts, test-keys, or root manager packages).
     */
    fun isDeviceRooted(context: Context? = null): Boolean {
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true
        }

        for (path in SU_PATHS) {
            try {
                if (File(path).exists()) return true
            } catch (_: Exception) {
            }
        }

        if (canExecuteSu()) {
            return true
        }

        if (context != null) {
            val pm = context.packageManager
            for (pkg in ROOT_PACKAGES) {
                try {
                    pm.getPackageInfo(pkg, 0)
                    return true
                } catch (_: PackageManager.NameNotFoundException) {
                } catch (_: Exception) {
                }
            }
        }

        return false
    }

    private fun canExecuteSu(): Boolean {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            reader.readLine() != null
        } catch (_: Throwable) {
            false
        } finally {
            process?.destroy()
        }
    }

    /**
     * Detects active Java/native debuggers or suspicious Frida/Xposed instrumentation in memory maps.
     */
    fun isTamperedOrHooked(context: Context? = null): Boolean {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            return true
        }
        try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists() && mapsFile.canRead()) {
                mapsFile.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        val lower = line.lowercase(Locale.US)
                        if (lower.contains("frida") || lower.contains("xposed") || lower.contains("substrate")) {
                            return true
                        }
                    }
                }
            }
        } catch (_: Throwable) {
        }

        if (context != null) {
            val pkg = context.packageName
            // Allow official package ID and test environment package IDs
            if (pkg != "com.customtunnelpro.vpn" && pkg != "com.example") {
                return true
            }
        }
        return false
    }

    fun isDebuggable(context: Context): Boolean {
        return (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }
}
