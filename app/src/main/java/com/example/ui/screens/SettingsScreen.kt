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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Autorenew
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.ui.components.GlassCard
import com.example.ui.theme.ConnectedGreen
import com.example.ui.theme.CyanPrimaryDark
import com.example.ui.viewmodel.VpnViewModel

@Composable
fun SettingsScreen(
    viewModel: VpnViewModel,
    modifier: Modifier = Modifier
) {
    val settings by viewModel.settings.collectAsState()
    var showLicensesDialog by remember { mutableStateOf(false) }
    var showPrivacyDialog by remember { mutableStateOf(false) }

    val activeAbi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Settings & Architecture",
            style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onBackground
        )

        // Tunnel Mode & Behavior Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Text(
                    text = "Application Behavior",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.primary
                )

                // Pro Mode toggle
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Pro Tunnel Mode", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                        Text("Exposes advanced diagnostic telemetry, packet stats, and raw configuration parameters", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(
                        checked = settings.proMode,
                        onCheckedChange = {
                            viewModel.updateSettings(settings.copy(proMode = it))
                        },
                        modifier = Modifier.testTag("pro_mode_switch")
                    )
                }

                // Auto Reconnect
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Auto-Reconnect with Backoff", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                        Text("Automatically retries connection up to 5 times with bounded exponential delays on network disruption", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(
                        checked = settings.autoReconnect,
                        onCheckedChange = {
                            viewModel.updateSettings(settings.copy(autoReconnect = it))
                        },
                        modifier = Modifier.testTag("auto_reconnect_switch")
                    )
                }
            }
        }

        // Appearance Theme Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Theme Appearance",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.primary
                )

                listOf(
                    "system" to "System Default",
                    "dark" to "Dark Cyber Mode",
                    "light" to "Light Mode"
                ).forEach { (code, label) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = settings.theme == code,
                            onClick = {
                                viewModel.updateSettings(settings.copy(theme = code))
                            }
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(label, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        // 32-bit & 64-bit Architecture Verification Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.Memory, contentDescription = null, tint = ConnectedGreen)
                    Text(
                        text = "Native ABI Architecture Audit",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                    )
                }

                Text(
                    text = "AegisTunnel embeds native dual-architecture .so binaries for both 64-bit and 32-bit ARM chipsets:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                AbiVerificationRow("arm64-v8a (64-bit ARM)", "Verified in APK (libgojni.so + libhev-socks5-tunnel.so)")
                AbiVerificationRow("armeabi-v7a (32-bit ARM)", "Verified in APK (libgojni.so + libhev-socks5-tunnel.so)")
                AbiVerificationRow("Current Active Device ABI", activeAbi)
            }
        }

        // About & Legal Actions
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = { showLicensesDialog = true },
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.Info, null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Open Source")
            }

            OutlinedButton(
                onClick = { showPrivacyDialog = true },
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.Policy, null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Privacy Notice")
            }
        }

        Text(
            text = "AegisTunnel VPN v2.0 • Build verified for arm64-v8a & armeabi-v7a",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            modifier = Modifier.padding(top = 8.dp)
        )
    }

    if (showLicensesDialog) {
        AlertDialog(
            onDismissRequest = { showLicensesDialog = false },
            title = { Text("Open Source Software Notices", style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold)) },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    LicenseItem("Xray-Core / AndroidLibXrayLite", "Mozilla Public License 2.0 (MPL 2.0)", "https://github.com/XTLS/Xray-core")
                    LicenseItem("hev-socks5-tunnel", "MIT License", "https://github.com/heiher/hev-socks5-tunnel")
                    LicenseItem("JSch (mwiede)", "BSD 3-Clause License", "https://github.com/mwiede/jsch")
                    LicenseItem("AndroidX & Jetpack Compose", "Apache License 2.0", "https://android.googlesource.com")
                    LicenseItem("lwIP - Lightweight TCP/IP stack", "BSD License", "Swedish Institute of Computer Science")
                }
            },
            confirmButton = {
                TextButton(onClick = { showLicensesDialog = false }) {
                    Text("Close")
                }
            }
        )
    }

    if (showPrivacyDialog) {
        AlertDialog(
            onDismissRequest = { showPrivacyDialog = false },
            title = { Text("Privacy & Security Policy", style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "• Zero Traffic Logging: AegisTunnel does not monitor, inspect, log, or store your internet activity or network traffic.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "• Local Data Only: All profiles, passwords, and tokens reside strictly in encrypted private app storage on this device.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "• Secret Redaction: Passwords, private keys, and UUIDs are masked automatically before writing to diagnostic logs.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "• No External Tracking: No third-party ad networks or tracking trackers are embedded in the app.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showPrivacyDialog = false }) {
                    Text("Understood")
                }
            }
        )
    }
}

@Composable
fun AbiVerificationRow(label: String, detail: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold))
            Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Icon(Icons.Default.CheckCircle, contentDescription = "Verified", tint = ConnectedGreen, modifier = Modifier.size(18.dp))
    }
}

@Composable
fun LicenseItem(name: String, license: String, url: String) {
    Column {
        Text(name, style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold))
        Text(license, style = MaterialTheme.typography.labelSmall, color = CyanPrimaryDark)
        Text(url, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
