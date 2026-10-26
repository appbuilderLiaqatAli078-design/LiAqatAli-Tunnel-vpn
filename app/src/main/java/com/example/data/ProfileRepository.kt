package com.example.data

import android.content.Context
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.parser.ConfigParser
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
import java.util.UUID

class ProfileRepository(private val context: Context) {
    private val TAG = "ProfileRepo"
    private val file = File(context.filesDir, "vpn_profiles.json")

    private val _profiles = MutableStateFlow<List<VpnProfile>>(emptyList())
    val profiles: StateFlow<List<VpnProfile>> = _profiles.asStateFlow()

    init {
        loadProfiles()
    }

    private fun loadProfiles() {
        if (!file.exists()) {
            val starterProfiles = getStarterProfiles()
            _profiles.value = starterProfiles
            saveProfilesToFile(starterProfiles)
            return
        }

        try {
            val text = file.readText()
            val array = JSONArray(text)
            val list = mutableListOf<VpnProfile>()
            for (i in 0 until array.length()) {
                val objStr = array.getJSONObject(i).toString()
                val parsed = ConfigParser.parse(objStr)
                if (parsed is com.example.parser.ParseResult.Success) {
                    list.add(parsed.profile)
                }
            }
            if (list.isEmpty()) {
                val starterProfiles = getStarterProfiles()
                _profiles.value = starterProfiles
                saveProfilesToFile(starterProfiles)
            } else {
                _profiles.value = list
            }
        } catch (e: Exception) {
            AppLogger.e(TAG, "Failed to load profiles, generating starter profiles: ${e.message}")
            val starter = getStarterProfiles()
            _profiles.value = starter
            saveProfilesToFile(starter)
        }
    }

    fun saveProfile(profile: VpnProfile) {
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
            FileOutputStream(file).use { it.write(array.toString(2).toByteArray()) }
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
            AppLogger.w(TAG, "Ping failed for ${profile.name} (${profile.server}:${profile.port}): ${e.message}")
            val updated = profile.copy(lastPingMs = -1L)
            saveProfile(updated)
            null
        }
    }

    private fun getStarterProfiles(): List<VpnProfile> {
        return listOf(
            VpnProfile(
                id = UUID.randomUUID().toString(),
                name = "Cloudflare VLESS WS Template",
                protocol = ProtocolType.VLESS,
                server = "104.16.132.229",
                port = 443,
                password = "d342d110-d4a3-4513-bfa6-07a5e0f0ff37",
                security = "tls",
                network = "ws",
                path = "/vless-ws",
                sni = "cf-tunnel.aegis.net",
                dnsPrimary = "1.1.1.1",
                dnsSecondary = "8.8.8.8"
            ),
            VpnProfile(
                id = UUID.randomUUID().toString(),
                name = "SSH HTTP Custom Injector Template",
                protocol = ProtocolType.SSH,
                server = "128.199.192.1",
                port = 22,
                sshUsername = "vpnuser",
                password = "demoPassword123",
                sshPayload = "CONNECT [host_port] HTTP/1.1[crlf]Host: bug.isp.com[crlf]User-Agent: [ua][crlf]Connection: Upgrade[crlf][crlf]",
                proxyHost = "",
                proxyPort = 0
            ),
            VpnProfile(
                id = UUID.randomUUID().toString(),
                name = "Trojan Secure Gateway",
                protocol = ProtocolType.TROJAN,
                server = "gateway.aegistunnel.org",
                port = 443,
                password = "aegisTrojanPasswd987",
                security = "tls",
                sni = "gateway.aegistunnel.org"
            )
        )
    }
}
