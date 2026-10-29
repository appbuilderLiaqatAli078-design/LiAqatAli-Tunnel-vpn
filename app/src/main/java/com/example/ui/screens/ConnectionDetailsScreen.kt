package com.example.ui.screens

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Route
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.VpnState
import com.example.ui.components.GlassCard
import com.example.ui.components.formatBytes
import com.example.ui.components.formatSpeed
import com.example.ui.theme.ConnectedGreen
import com.example.ui.theme.CyanPrimaryDark
import com.example.ui.theme.DisconnectedRed
import com.example.ui.viewmodel.VpnViewModel

import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.IconButton

@Composable
fun ConnectionDetailsScreen(
    viewModel: VpnViewModel,
    onNavigateBack: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val vpnState by viewModel.vpnState.collectAsState()
    val trafficStats by viewModel.trafficStats.collectAsState()
    val selectedProfile by viewModel.selectedProfile.collectAsState()

    val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (onNavigateBack != null) {
                IconButton(onClick = onNavigateBack) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = "Back",
                        tint = MaterialTheme.colorScheme.onBackground
                    )
                }
            }
            Text(
                text = "Connection Diagnostics",
                style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onBackground
            )
        }

        // Engine Status Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = if (vpnState is VpnState.Connected) ConnectedGreen else CyanPrimaryDark
                    )
                    Text(
                        text = "Active Engine & Architecture",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }

                val statusLabel = when (val st = vpnState) {
                    is VpnState.Connected -> if (st.isInternetVerified) {
                        "Active • Internet Verified"
                    } else {
                        "Tunnel Connected • Internet Unverified (${st.verificationDetail})"
                    }
                    is VpnState.TunnelEstablished -> "Tunnel Established • Verifying Internet"
                    else -> "Standby"
                }
                DetailRow("Status", statusLabel)
                DetailRow("Primary Engine", if (selectedProfile?.protocol == com.example.model.ProtocolType.SSH) "SSH Engine (${selectedProfile?.sshMode?.badge ?: "DIRECT"})" else "Xray Core v26 JNI")
                if (selectedProfile?.protocol == com.example.model.ProtocolType.SSH) {
                    DetailRow("SSH Tunnel Mode", selectedProfile?.sshMode?.displayName ?: "Direct")
                    if (selectedProfile?.proxyHost?.isNotBlank() == true) {
                        DetailRow("Outbound Proxy", "••••••••••••")
                    }
                    if (selectedProfile?.sshSni?.isNotBlank() == true) {
                        DetailRow("TLS SNI Host", "••••••••••••")
                    }
                }
                DetailRow("TUN Forwarder", "HEV SOCKS5 Tunnel v2.19.3 (C/lwIP)")
                DetailRow("Device ABI", "$abi (${if (abi.contains("64")) "64-bit ARM" else "32-bit ARM"})")
                DetailRow("Socket Protection", "VpnService.protect() Active")
            }
        }

        // Live Traffic Statistics Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.NetworkCheck, contentDescription = null, tint = CyanPrimaryDark)
                    Text(
                        text = "Traffic Telemetry",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    MetricBox(
                        label = "Transmitted (Tx)",
                        value = formatBytes(trafficStats.bytesOut),
                        speed = formatSpeed(trafficStats.speedOutBytesPerSec),
                        packets = "${trafficStats.packetsOut} pkts",
                        icon = Icons.Default.ArrowUpward,
                        modifier = Modifier.weight(1f)
                    )

                    MetricBox(
                        label = "Received (Rx)",
                        value = formatBytes(trafficStats.bytesIn),
                        speed = formatSpeed(trafficStats.speedInBytesPerSec),
                        packets = "${trafficStats.packetsIn} pkts",
                        icon = Icons.Default.ArrowDownward,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        // TUN Network Configuration Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.Route, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
                    Text(
                        text = "TUN Interface Configuration",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }

                DetailRow("Interface Address", "198.18.0.1 / 24")
                DetailRow("Route Mask", "0.0.0.0 / 0 (Global IPv4)")
                DetailRow("Tunnel MTU", "1500 bytes")
                DetailRow("Tunnel DNS", selectedProfile?.dnsPrimary ?: "1.1.1.1")
                DetailRow("Secondary DNS", selectedProfile?.dnsSecondary?.ifBlank { "8.8.8.8" } ?: "8.8.8.8")
                DetailRow("IPv6 Mode", if (selectedProfile?.blockIpv6 == false) "Tunneling (::/0)" else "Leak Protection (Isolated)")
            }
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.42f),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium.copy(
                fontWeight = FontWeight.SemiBold,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp
            ),
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(0.58f),
            textAlign = TextAlign.End,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
fun MetricBox(
    label: String,
    value: String,
    speed: String,
    packets: String,
    icon: ImageVector,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Icon(icon, contentDescription = null, modifier = Modifier.size(14.dp), tint = CyanPrimaryDark)
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = speed,
                style = MaterialTheme.typography.labelMedium.copy(color = CyanPrimaryDark, fontWeight = FontWeight.SemiBold),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = packets,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
