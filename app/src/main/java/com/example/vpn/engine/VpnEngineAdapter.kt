package com.example.vpn.engine

import com.example.model.VpnProfile
import com.example.vpn.CustomTunnelVpnService

enum class ProbeFailureCategory {
    NONE,
    TIMEOUT,
    DNS_FAILURE,
    CONNECTION_REFUSED,
    CLOSED_PIPE,
    TLS_HANDSHAKE,
    WEBSOCKET_HANDSHAKE,
    AUTH_OR_PROTOCOL,
    BLOCKED_PROBE
}

data class ConnectivityCheckResult(
    val verified: Boolean,
    val rttMs: Long? = null,
    val endpoint: String? = null,
    val failureCategory: ProbeFailureCategory = ProbeFailureCategory.NONE,
    val diagnosticMessage: String = if (verified) "Internet Verified" else "Internet Unverified"
)

interface VpnEngineAdapter {
    fun getEngineName(): String
    fun getLocalSocksPort(): Int
    suspend fun start(profile: VpnProfile, vpnService: CustomTunnelVpnService, tunFd: Int): Boolean
    suspend fun stop()
    fun isRunning(): Boolean
    fun getLastConnectivityResult(): ConnectivityCheckResult? = null
    suspend fun recheckConnectivity(): ConnectivityCheckResult? = null
}

