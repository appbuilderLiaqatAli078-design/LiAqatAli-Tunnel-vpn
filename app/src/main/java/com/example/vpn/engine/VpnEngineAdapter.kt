package com.example.vpn.engine

import com.example.model.VpnProfile
import com.example.vpn.CustomTunnelVpnService

interface VpnEngineAdapter {
    fun getEngineName(): String
    fun getLocalSocksPort(): Int
    suspend fun start(profile: VpnProfile, vpnService: CustomTunnelVpnService, tunFd: Int): Boolean
    suspend fun stop()
    fun isRunning(): Boolean
}
