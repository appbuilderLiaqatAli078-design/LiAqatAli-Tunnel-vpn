package com.example

import android.app.Application
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.data.AppLogger
import com.example.data.ProfileRepository
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.parser.ConfigParser
import com.example.parser.ParseResult
import com.example.security.CtpConfigCrypto
import com.example.security.CtpExportOptions
import com.example.security.DeviceSecurityManager
import com.example.ui.viewmodel.VpnViewModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleRobolectricTest {

    @Test
    fun `read string from context`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        val devName = context.getString(R.string.developer_name)
        val telegram = context.getString(R.string.telegram_handle)
        assertEquals("Custom Tunnel Pro", appName)
        assertEquals("Liaqat Ali", devName)
        assertEquals("@LiaqatAliPro", telegram)
    }

    @Test
    fun `selected profile edgetunnel persists across app restarts and encrypted on disk`() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val repo1 = ProfileRepository(app)

        val edgeTunnelProfile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = "edgetunnel",
            protocol = ProtocolType.VLESS,
            server = "secret-edge-host.example.com",
            port = 443,
            password = "d342d110-d4a3-4513-bfa6-07a5e0f0ff37",
            security = "tls",
            network = "ws"
        )
        val anotherProfile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = "other-profile-top",
            protocol = ProtocolType.TROJAN,
            server = "other.example.com",
            port = 443,
            password = "other-password"
        )

        // Save edgetunnel first, then save anotherProfile at index 0 (top of list)
        repo1.saveProfile(edgeTunnelProfile)
        repo1.saveProfile(anotherProfile)

        // User selects edgetunnel (which is NOT the first item in the list)
        val vm1 = VpnViewModel(app)
        vm1.selectProfile(edgeTunnelProfile)
        assertEquals("edgetunnel", vm1.selectedProfile.value?.name)

        // Verify vpn_profiles.json on disk is encrypted at rest and never leaks plaintext host
        val storedFile = File(app.filesDir, "vpn_profiles.json")
        assertTrue(storedFile.exists())
        val rawDiskText = storedFile.readText()
        assertTrue(rawDiskText.startsWith("CTP_STORE_V2:"))
        assertFalse("Plaintext host must not appear on disk", rawDiskText.contains("secret-edge-host.example.com"))

        // Simulate app process death and cold restart hours later
        val vm2 = VpnViewModel(app)
        assertNotNull(vm2.selectedProfile.value)
        assertEquals("edgetunnel", vm2.selectedProfile.value?.name)
        assertEquals(edgeTunnelProfile.id, vm2.selectedProfile.value?.id)
    }

    @Test
    fun `ctp encrypted config export import and security locks work properly`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val hwid = DeviceSecurityManager.getHardwareId(context)
        assertTrue(hwid.startsWith("CTP-"))

        val sourceProfile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = "Pro Locked SSH",
            protocol = ProtocolType.SSH,
            server = "hidden-vip-server.customtunnelpro.vpn",
            port = 80,
            sshUsername = "vipuser",
            password = "vipSecretPassword99",
            sshPayload = "GET / HTTP/1.1[crlf]Host: bug.host.net[crlf]Upgrade: websocket[crlf][crlf]"
        )

        // 1. Export locked + password-protected .ctp config bound to this device's HWID
        val ctpEncrypted = ConfigParser.exportProfileToCtp(
            profile = sourceProfile,
            options = CtpExportOptions(
                lockConfig = true,
                expiresAtMillis = System.currentTimeMillis() + 86_400_000L,
                unlockPassword = "MySecretUnlockPassword",
                requirePasswordOnImport = true,
                lockedHwid = hwid,
                blockRoot = false,
                creatorMessage = "Config by @LiaqatAliPro"
            )
        )

        assertTrue(ctpEncrypted.startsWith("CTP2:"))
        // Ensure zero plaintext leakage inside the exported .ctp file
        assertFalse(ctpEncrypted.contains("hidden-vip-server.customtunnelpro.vpn"))
        assertFalse(ctpEncrypted.contains("vipSecretPassword99"))
        assertFalse(ctpEncrypted.contains("bug.host.net"))

        // 2. Parsing without password must return requiresPassword = true
        val noPwdResult = ConfigParser.parse(ctpEncrypted, unlockPassword = "", context = context)
        assertTrue(noPwdResult is ParseResult.Failure)
        assertTrue((noPwdResult as ParseResult.Failure).requiresPassword)

        // 3. Parsing with wrong password must fail
        val wrongPwdResult = ConfigParser.parse(ctpEncrypted, unlockPassword = "WrongPassword", context = context)
        assertTrue(wrongPwdResult is ParseResult.Failure)

        // 4. Parsing with correct password succeeds and preserves lock + creator note
        val validResult = ConfigParser.parse(ctpEncrypted, unlockPassword = "MySecretUnlockPassword", context = context)
        assertTrue(validResult is ParseResult.Success)
        val imported = (validResult as ParseResult.Success).profile
        assertEquals("Pro Locked SSH", imported.name)
        assertEquals("hidden-vip-server.customtunnelpro.vpn", imported.server)
        assertEquals("vipSecretPassword99", imported.password)
        assertTrue(imported.isLocked)
        assertEquals("Config by @LiaqatAliPro", imported.creatorMessage)
        assertEquals("••••••••••••", imported.maskedEndpoint)
        assertTrue(CtpConfigCrypto.verifyUnlockPassword("MySecretUnlockPassword", imported.lockPasswordHash))
        assertFalse(CtpConfigCrypto.verifyUnlockPassword("BadPass", imported.lockPasswordHash))

        // 5. Expired .ctp config must be rejected
        val expiredCtp = ConfigParser.exportProfileToCtp(
            profile = sourceProfile,
            options = CtpExportOptions(
                lockConfig = true,
                expiresAtMillis = System.currentTimeMillis() - 10_000L
            )
        )
        val expiredResult = ConfigParser.parse(expiredCtp, context = context)
        assertTrue(expiredResult is ParseResult.Failure)
        assertTrue((expiredResult as ParseResult.Failure).reason.contains("expired", ignoreCase = true))

        // 6. Mismatched HWID .ctp config must be rejected
        val wrongHwidCtp = ConfigParser.exportProfileToCtp(
            profile = sourceProfile,
            options = CtpExportOptions(
                lockConfig = true,
                lockedHwid = "CTP-0000-0000-0000"
            )
        )
        val wrongHwidResult = ConfigParser.parse(wrongHwidCtp, context = context)
        assertTrue(wrongHwidResult is ParseResult.Failure)
        assertTrue((wrongHwidResult as ParseResult.Failure).reason.contains("Hardware ID", ignoreCase = true))
    }

    @Test
    fun `host masking redacts registered hosts and headers in AppLogger`() {
        AppLogger.registerSensitiveHosts("my-secret-node.customtunnelpro.vpn", "198.51.100.77")
        val logMsg = "Connecting to my-secret-node.customtunnelpro.vpn:443 via 198.51.100.77 with Host: bug.cdn.org"
        val redacted = AppLogger.redact(logMsg)
        assertFalse(redacted.contains("my-secret-node.customtunnelpro.vpn"))
        assertFalse(redacted.contains("198.51.100.77"))
        assertFalse(redacted.contains("bug.cdn.org"))
        assertTrue(redacted.contains("••••••••••••"))
    }
}
