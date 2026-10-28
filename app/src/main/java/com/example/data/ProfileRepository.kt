package com.example.data

import android.content.Context
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.parser.ConfigParser
import com.example.security.CtpConfigCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.io.File
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.UUID

class ProfileRepository(private val context: Context) {
    private val TAG = "ProfileRepo"
    private val file = File(context.filesDir, "vpn_profiles.json")
    private val prefs = context.getSharedPreferences("ctp_profile_prefs", Context.MODE_PRIVATE)

    private val _profiles = MutableStateFlow<List<VpnProfile>>(emptyList())
    val profiles: StateFlow<List<VpnProfile>> = _profiles.asStateFlow()

    init {
        loadProfiles()
    }

    fun getSelectedProfileId(): String? {
        return prefs.getString(KEY_SELECTED_PROFILE_ID, null)
    }

    fun setSelectedProfileId(profileId: String?) {
        prefs.edit().putString(KEY_SELECTED_PROFILE_ID, profileId).apply()
    }

    private fun registerHostsForMasking(list: List<VpnProfile>) {
        list.forEach { p ->
            AppLogger.registerSensitiveHosts(
                p.server,
                p.sni,
                p.wsHost,
                p.sshSni,
                p.proxyHost,
                p.sshChainProxyHost
            )
        }
    }

    private fun loadProfiles() {
        if (!file.exists()) {
            val starterProfiles = getStarterProfiles()
            registerHostsForMasking(starterProfiles)
            _profiles.value = starterProfiles
            if (getSelectedProfileId() == null && starterProfiles.isNotEmpty()) {
                setSelectedProfileId(starterProfiles.first().id)
            }
            saveProfilesToFile(starterProfiles)
            return
        }

        try {
            val rawText = file.readText()
            val decryptedJson = CtpConfigCrypto.decryptLocalStore(rawText, context)
            val array = JSONArray(decryptedJson)
            val list = mutableListOf<VpnProfile>()
            for (i in 0 until array.length()) {
                val objStr = array.getJSONObject(i).toString()
                val parsed = ConfigParser.parse(objStr, context = context)
                if (parsed is com.example.parser.ParseResult.Success) {
                    list.add(parsed.profile)
                }
            }
            if (list.isEmpty()) {
                val starterProfiles = getStarterProfiles()
                registerHostsForMasking(starterProfiles)
                _profiles.value = starterProfiles
                if (getSelectedProfileId() == null && starterProfiles.isNotEmpty()) {
                    setSelectedProfileId(starterProfiles.first().id)
                }
                saveProfilesToFile(starterProfiles)
            } else {
                registerHostsForMasking(list)
                _profiles.value = list
                // Re-save if file was legacy unencrypted JSON
                if (!rawText.trim().startsWith("CTP_STORE_V2:")) {
                    saveProfilesToFile(list)
                }
            }
        } catch (e: Exception) {
            AppLogger.e(TAG, "Failed to load profiles, generating starter profiles: ${e.message}")
            val starter = getStarterProfiles()
            registerHostsForMasking(starter)
            _profiles.value = starter
            saveProfilesToFile(starter)
        }
    }

    fun saveProfile(profile: VpnProfile) {
        AppLogger.registerSensitiveHosts(
            profile.server,
            profile.sni,
            profile.wsHost,
            profile.sshSni,
            profile.proxyHost,
            profile.sshChainProxyHost
        )
        val current = _profiles.value.toMutableList()
        val index = current.indexOfFirst { it.id == profile.id }
        if (index >= 0) {
            current[index] = profile
        } else {
            current.add(0, profile)
        }
        _profiles.value = current
        saveProfilesToFile(current)
    }

    fun deleteProfile(id: String) {
        val updated = _profiles.value.filterNot { it.id == id }
        _profiles.value = updated
        if (getSelectedProfileId() == id) {
            setSelectedProfileId(updated.firstOrNull()?.id)
        }
        saveProfilesToFile(updated)
    }

    fun duplicateProfile(profile: VpnProfile): VpnProfile {
        val duplicate = profile.copy(
            id = UUID.randomUUID().toString(),
            name = "${profile.name} (Copy)",
            createdAt = System.currentTimeMillis()
        )
        saveProfile(duplicate)
        return duplicate
    }

    private fun saveProfilesToFile(list: List<VpnProfile>) {
        try {
            val array = JSONArray()
            list.forEach { profile ->
                val jsonStr = ConfigParser.exportProfileToJson(profile)
                array.put(org.json.JSONObject(jsonStr))
            }
            val encryptedPayload = CtpConfigCrypto.encryptLocalStore(array.toString(), context)
            FileOutputStream(file).use { it.write(encryptedPayload.toByteArray(StandardCharsets.UTF_8)) }
        } catch (e: Exception) {
            AppLogger.e(TAG, "Error saving profiles to file: ${e.message}")
        }
    }

    suspend fun pingProfile(profile: VpnProfile): Long? = withContext(Dispatchers.IO) {
        try {
            val startTime = System.currentTimeMillis()
            val socket = Socket()
            socket.connect(InetSocketAddress(profile.server, profile.port), 3500)
            val latency = System.currentTimeMillis() - startTime
            socket.close()

            // Update profile with latency
            val updated = profile.copy(lastPingMs = latency)
            saveProfile(updated)
            latency
        } catch (e: Exception) {
            AppLogger.w(TAG, "Ping failed for ${profile.name} (••••••••••••): ${e.message}")
            val updated = profile.copy(lastPingMs = -1L)
            saveProfile(updated)
            null
        }
    }

    private fun deterministicUuid(seed: String): String {
        return UUID.nameUUIDFromBytes(seed.toByteArray(StandardCharsets.UTF_8)).toString()
    }

    private fun getStarterProfiles(): List<VpnProfile> {
        return listOf(
            VpnProfile(
                id = deterministicUuid("starter-cloudflare-vless-ws"),
                name = "Cloudflare VLESS WS Template",
                protocol = ProtocolType.VLESS,
                server = "104.16.132.229",
                port = 443,
                password = "d342d110-d4a3-4513-bfa6-07a5e0f0ff37",
                security = "tls",
                network = "ws",
                path = "/vless-ws",
                sni = "cf-tunnel.customtunnelpro.org",
                dnsPrimary = "1.1.1.1",
                dnsSecondary = "8.8.8.8"
            ),
            VpnProfile(
                id = deterministicUuid("starter-ssh-custom-injector"),
                name = "SSH HTTP Custom Injector Template",
                protocol = ProtocolType.SSH,
                server = "128.199.192.1",
                port = 22,
                sshMode = com.example.model.SshTunnelMode.CUSTOM_PAYLOAD,
                sshUsername = "vpnuser",
                password = "demoPassword123",
                sshPayload = "CONNECT [host_port] HTTP/1.1[crlf]Host: bug.isp.com[crlf]User-Agent: [ua][crlf]Connection: Upgrade[crlf][crlf]",
                proxyHost = "",
                proxyPort = 0
            ),
            VpnProfile(
                id = deterministicUuid("starter-ssh-wss"),
                name = "SSH Secure WebSocket (WSS)",
                protocol = ProtocolType.SSH,
                server = "ssh-wss.customtunnelpro.org",
                port = 443,
                sshMode = com.example.model.SshTunnelMode.SECURE_WEBSOCKET,
                sshUsername = "tunneluser",
                password = "wssPassword456",
                sshSni = "ssh-wss.customtunnelpro.org",
                sshWsPath = "/ssh"
            ),
            VpnProfile(
                id = deterministicUuid("starter-trojan-gateway"),
                name = "Trojan Secure Gateway",
                protocol = ProtocolType.TROJAN,
                server = "gateway.customtunnelpro.org",
                port = 443,
                password = "customTrojanPasswd987",
                security = "tls",
                sni = "gateway.customtunnelpro.org"
            )
        )
    }

    companion object {
        private const val KEY_SELECTED_PROFILE_ID = "selected_profile_id"
    }
}
