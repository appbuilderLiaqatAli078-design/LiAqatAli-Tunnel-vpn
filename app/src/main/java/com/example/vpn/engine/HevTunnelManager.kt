package com.example.vpn.engine

import android.content.Context
import com.example.data.AppLogger
import com.example.model.TrafficStats
import hev.htproxy.TProxyService
import java.io.File
import java.io.FileOutputStream

object HevTunnelManager {
    private const val TAG = "HevTunnel"
    private var lastRxBytes = 0L
    private var lastTxBytes = 0L
    private var lastTimestamp = 0L

    fun buildConfigYaml(
        socksAddress: String = "127.0.0.1",
        socksPort: Int = 10808,
        udpMode: String = "udp"
    ): String {
        val normalizedUdp = if (udpMode == "udp" || udpMode == "tcp") udpMode else "udp"
        return """
            tunnel:
              name: tun0
              mtu: 1500
              multi-queue: false
              ipv4: 198.18.0.1
            socks5:
              port: $socksPort
              address: '$socksAddress'
              udp: '$normalizedUdp'
            misc:
              task-stack-size: 81920
              tcp-buffer-size: 65536
              connect-timeout: 10000
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
              log-level: warn
        """.trimIndent()
    }

    fun start(
        context: Context,
        tunFd: Int,
        socksAddress: String = "127.0.0.1",
        socksPort: Int = 10808,
        udpMode: String = "tcp"
    ): Boolean {
        return try {
            val configFile = File(context.cacheDir, "hev_socks5.yml")
            val yamlConfig = buildConfigYaml(socksAddress, socksPort, udpMode)

            FileOutputStream(configFile).use { it.write(yamlConfig.toByteArray()) }

            AppLogger.i(TAG, "Starting HEV SOCKS5 Tunnel forwarder pointing to $socksAddress:$socksPort (udp=$udpMode, tunFd=$tunFd)")
            val success = TProxyService.TProxyStartService(configFile.absolutePath, tunFd)
            if (success) {
                AppLogger.i(TAG, "HEV SOCKS5 Tunnel forwarder started successfully")
            } else {
                AppLogger.e(TAG, "HEV SOCKS5 Tunnel failed to start via JNI")
            }
            success
        } catch (e: Throwable) {
            AppLogger.e(TAG, "Exception starting HEV SOCKS5 Tunnel", e)
            false
        }
    }

    fun isRunning(): Boolean {
        return try {
            TProxyService.TProxyIsRunning()
        } catch (e: Throwable) {
            false
        }
    }

    fun stop() {
        try {
            if (isRunning()) {
                AppLogger.i(TAG, "Stopping HEV SOCKS5 Tunnel forwarder")
                TProxyService.TProxyStopService()
            }
        } catch (e: Throwable) {
            AppLogger.e(TAG, "Exception stopping HEV SOCKS5 Tunnel", e)
        }
    }

    fun getStats(): TrafficStats {
        return try {
            val stats = TProxyService.TProxyGetStats()
            if (stats != null && stats.size >= 4) {
                val txPackets = stats[0]
                val txBytes = stats[1]
                val rxPackets = stats[2]
                val rxBytes = stats[3]

                val now = System.currentTimeMillis()
                val elapsedSec = if (lastTimestamp > 0) (now - lastTimestamp).coerceAtLeast(1) / 1000.0 else 1.0
                val speedIn = if (lastRxBytes > 0 && rxBytes >= lastRxBytes) ((rxBytes - lastRxBytes) / elapsedSec).toLong() else 0L
                val speedOut = if (lastTxBytes > 0 && txBytes >= lastTxBytes) ((txBytes - lastTxBytes) / elapsedSec).toLong() else 0L

                lastRxBytes = rxBytes
                lastTxBytes = txBytes
                lastTimestamp = now

                TrafficStats(
                    bytesIn = rxBytes,
                    bytesOut = txBytes,
                    speedInBytesPerSec = speedIn,
                    speedOutBytesPerSec = speedOut,
                    packetsIn = rxPackets,
                    packetsOut = txPackets
                )
            } else {
                TrafficStats()
            }
        } catch (e: Throwable) {
            TrafficStats()
        }
    }
}
