package com.example

import com.example.data.AppLogger
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.model.VpnState
import com.example.parser.ConfigParser
import com.example.parser.ParseResult
import com.example.vpn.engine.PayloadInjector
import com.example.vpn.engine.XrayEngineAdapter
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleUnitTest {

    @Test
    fun testVlessConfigParser() {
        val vlessUri = "vless://d342d110-d4a3-4513-bfa6-07a5e0f0ff37@example.com:443?security=tls&type=ws&sni=example.com&path=/vless#MyVlessNode"
        val result = ConfigParser.parse(vlessUri)

        assertTrue(result is ParseResult.Success)
        val profile = (result as ParseResult.Success).profile
        assertEquals("MyVlessNode", profile.name)
        assertEquals(ProtocolType.VLESS, profile.protocol)
        assertEquals("example.com", profile.server)
        assertEquals(443, profile.port)
        assertEquals("d342d110-d4a3-4513-bfa6-07a5e0f0ff37", profile.password)
        assertEquals("tls", profile.security)
        assertEquals("ws", profile.network)
        assertEquals("/vless", profile.path)
        assertEquals("example.com", profile.sni)
    }

    @Test
    fun testTrojanConfigParser() {
        val trojanUri = "trojan://secretPass123@gateway.trojan.org:443?sni=gateway.trojan.org#SecureTrojan"
        val result = ConfigParser.parse(trojanUri)

        assertTrue(result is ParseResult.Success)
        val profile = (result as ParseResult.Success).profile
        assertEquals("SecureTrojan", profile.name)
        assertEquals(ProtocolType.TROJAN, profile.protocol)
        assertEquals("gateway.trojan.org", profile.server)
        assertEquals(443, profile.port)
        assertEquals("secretPass123", profile.password)
    }

    @Test
    fun testSshConfigParser() {
        val sshUri = "ssh://root:mySecretPass@192.168.1.100:22#SSH-Direct"
        val result = ConfigParser.parse(sshUri)

        assertTrue(result is ParseResult.Success)
        val profile = (result as ParseResult.Success).profile
        assertEquals("SSH-Direct", profile.name)
        assertEquals(ProtocolType.SSH, profile.protocol)
        assertEquals("192.168.1.100", profile.server)
        assertEquals(22, profile.port)
        assertEquals("root", profile.sshUsername)
        assertEquals("mySecretPass", profile.password)
    }

    @Test
    fun testInvalidConfigParsingFailsGracefully() {
        val invalidUri = "unsupported://bad-protocol.com"
        val result = ConfigParser.parse(invalidUri)
        assertTrue(result is ParseResult.Failure)

        val emptyResult = ConfigParser.parse("")
        assertTrue(emptyResult is ParseResult.Failure)
    }

    @Test
    fun testPayloadInjectorMacroFormatting() {
        val raw = "GET / HTTP/1.1[crlf]Host: [host][crlf]X-Target: [host_port][crlf][crlf]"
        val formatted = PayloadInjector.formatPayload(raw, "api.myisp.com", 8080)

        assertTrue(formatted.contains("Host: api.myisp.com"))
        assertTrue(formatted.contains("X-Target: api.myisp.com:8080"))
        assertTrue(formatted.contains("\r\n"))
        assertFalse(formatted.contains("[crlf]"))
    }

    @Test
    fun testCredentialRedactionInLogger() {
        val sensitiveMsg = "User connected with uuid=d342d110-d4a3-4513-bfa6-07a5e0f0ff37 and password=SuperSecretPass! on ssh://user:secret123@1.2.3.4:22"
        val redacted = AppLogger.redact(sensitiveMsg)

        assertFalse(redacted.contains("SuperSecretPass!"))
        assertFalse(redacted.contains("d342d110-d4a3-4513-bfa6-07a5e0f0ff37"))
        assertFalse(redacted.contains("secret123"))
        assertTrue(redacted.contains("password=******"))
        assertTrue(redacted.contains(":******@"))
    }

    @Test
    fun testXrayConfigBuilderProducesValidJson() {
        val adapter = XrayEngineAdapter()
        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = "Test VLESS",
            protocol = ProtocolType.VLESS,
            server = "vpn.example.com",
            port = 443,
            password = "uuid-test-value",
            security = "tls",
            network = "ws",
            path = "/ws-path",
            sni = "vpn.example.com"
        )

        val jsonStr = adapter.buildXrayConfig(profile, 10808)
        val json = JSONObject(jsonStr)

        assertNotNull(json.optJSONArray("inbounds"))
        val inbounds = json.getJSONArray("inbounds")
        assertEquals(1, inbounds.length())
        assertEquals(10808, inbounds.getJSONObject(0).getInt("port"))
        assertEquals("socks", inbounds.getJSONObject(0).getString("protocol"))

        assertNotNull(json.optJSONArray("outbounds"))
        val outbounds = json.getJSONArray("outbounds")
        assertTrue(outbounds.length() >= 2)
        assertEquals("proxy", outbounds.getJSONObject(0).getString("tag"))
        assertEquals("vless", outbounds.getJSONObject(0).getString("protocol"))
    }

    @Test
    fun testVpnStateProperties() {
        val disconnected = VpnState.Disconnected
        assertFalse(disconnected.isConnected)
        assertFalse(disconnected.isBusy)

        val connecting = VpnState.Connecting("Test Server")
        assertFalse(connecting.isConnected)
        assertTrue(connecting.isBusy)

        val connected = VpnState.Connected("Test Server", System.currentTimeMillis(), "Xray")
        assertTrue(connected.isConnected)
        assertFalse(connected.isBusy)
    }
}
