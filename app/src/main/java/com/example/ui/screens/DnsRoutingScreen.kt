package com.example.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.ui.components.GlassCard
import com.example.ui.viewmodel.VpnViewModel

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun DnsRoutingScreen(
    viewModel: VpnViewModel,
    modifier: Modifier = Modifier
) {
    val settings by viewModel.settings.collectAsState()
    val selectedProfile by viewModel.selectedProfile.collectAsState()

    var customDns by remember(settings) { mutableStateOf(settings.customDns) }
    var selectedPreset by remember(settings) { mutableStateOf(settings.defaultDns) }
    var blockIpv6 by remember(settings) { mutableStateOf(settings.blockIpv6ByDefault) }
    var bypassLan by remember(settings) { mutableStateOf(settings.bypassLan) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "DNS & Routing Engine",
            style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onBackground
        )

        // DNS Provider Selection Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.Dns, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(
                        text = "Secure DNS Provider",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                    )
                }

                Text(
                    text = "All DNS queries inside the tunnel are encrypted and resolved through the selected upstream resolver.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    listOf(
                        "1.1.1.1" to "Cloudflare",
                        "8.8.8.8" to "Google",
                        "9.9.9.9" to "Quad9",
                        "94.140.14.14" to "AdGuard",
                        "custom" to "Custom"
                    ).forEach { (ip, name) ->
                        FilterChip(
                            selected = selectedPreset == ip,
                            onClick = {
                                selectedPreset = ip
                                val updated = settings.copy(
                                    defaultDns = if (ip == "custom") customDns else ip
                                )
                                viewModel.updateSettings(updated)
                            },
                            label = { Text("$name ($ip)") }
                        )
                    }
                }

                if (selectedPreset == "custom") {
                    OutlinedTextField(
                        value = customDns,
                        onValueChange = {
                            customDns = it
                            val updated = settings.copy(customDns = it, defaultDns = it)
                            viewModel.updateSettings(updated)
                        },
                        label = { Text("Custom DNS Server IP") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    )
                }
            }
        }

        // IPv6 Leak Protection Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Column {
                        Text(
                            text = "IPv6 Leak Isolation",
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                        )
                        Text(
                            text = "Blocks unintended IPv6 traffic from bypassing the VPN tunnel on dual-stack networks.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Switch(
                    checked = blockIpv6,
                    onCheckedChange = {
                        blockIpv6 = it
                        val updated = settings.copy(blockIpv6ByDefault = it)
                        viewModel.updateSettings(updated)
                    }
                )
            }
        }

        // LAN Bypass Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Default.Lan, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
                    Column {
                        Text(
                            text = "Bypass Local Network (LAN)",
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                        )
                        Text(
                            text = "Exclude private subnets (192.168.0.0/16, 10.0.0.0/8) to retain access to local printers and NAS devices.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Switch(
                    checked = bypassLan,
                    onCheckedChange = {
                        bypassLan = it
                        val updated = settings.copy(bypassLan = it)
                        viewModel.updateSettings(updated)
                    }
                )
            }
        }

        // Per-App Split Tunneling Info
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.FilterAlt, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
                    Text(
                        text = "Split Tunneling Policy",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                    )
                }
                Text(
                    text = "Device-wide routing is enabled by default. Individual profiles can be configured with specific package rules in the Profile Editor.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
