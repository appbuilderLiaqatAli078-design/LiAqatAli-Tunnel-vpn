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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.ui.components.GlassCard
import com.example.ui.theme.CyanPrimaryDark
import java.util.UUID

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ProfileEditScreen(
    initialProfile: VpnProfile?,
    defaultProtocol: ProtocolType = ProtocolType.VLESS,
    onSaveProfile: (VpnProfile) -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier
) {
    var name by remember { mutableStateOf(initialProfile?.name ?: "Custom Profile") }
    var protocol by remember { mutableStateOf(initialProfile?.protocol ?: defaultProtocol) }
    var server by remember { mutableStateOf(initialProfile?.server ?: "") }
    var portText by remember { mutableStateOf(initialProfile?.port?.toString() ?: if (protocol == ProtocolType.SSH) "22" else "443") }
    var password by remember { mutableStateOf(initialProfile?.password ?: "") }
    var security by remember { mutableStateOf(initialProfile?.security ?: if (protocol == ProtocolType.SSH) "none" else "tls") }
    var network by remember { mutableStateOf(initialProfile?.network ?: "tcp") }
    var sni by remember { mutableStateOf(initialProfile?.sni ?: "") }
    var path by remember { mutableStateOf(initialProfile?.path ?: "") }
    var pbk by remember { mutableStateOf(initialProfile?.publicKey ?: "") }

    // SSH Specific
    var sshUser by remember { mutableStateOf(initialProfile?.sshUsername ?: "root") }
    var sshPayload by remember { mutableStateOf(initialProfile?.sshPayload ?: "") }
    var proxyHost by remember { mutableStateOf(initialProfile?.proxyHost ?: "") }
    var proxyPortText by remember { mutableStateOf(initialProfile?.proxyPort?.let { if (it > 0) it.toString() else "" } ?: "") }

    // DNS & IPv6
    var dnsPrimary by remember { mutableStateOf(initialProfile?.dnsPrimary ?: "1.1.1.1") }
    var blockIpv6 by remember { mutableStateOf(initialProfile?.blockIpv6 ?: true) }
    var perAppProxy by remember { mutableStateOf(initialProfile?.perAppProxy ?: false) }
    var selectedAppsText by remember { mutableStateOf(initialProfile?.selectedApps?.joinToString(", ") ?: "") }

    var errorMessage by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = if (initialProfile == null) "New Profile" else "Edit Profile",
            style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onBackground
        )

        // Protocol selector chips
        Text(
            text = "Protocol Engine",
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            ProtocolType.values().forEach { proto ->
                FilterChip(
                    selected = protocol == proto,
                    onClick = {
                        protocol = proto
                        if (proto == ProtocolType.SSH && portText == "443") portText = "22"
                        if (proto != ProtocolType.SSH && portText == "22") portText = "443"
                    },
                    label = { Text(proto.displayName) },
                    leadingIcon = {
                        Icon(
                            imageVector = if (proto == ProtocolType.SSH) Icons.Default.Terminal else Icons.Default.Shield,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                )
            }
        }

        // Basic Profile Info
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text("Profile Name") },
            modifier = Modifier.fillMaxWidth().testTag("edit_profile_name"),
            shape = RoundedCornerShape(12.dp)
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = server,
                onValueChange = { server = it },
                label = { Text("Server Host / IP") },
                modifier = Modifier.weight(2f).testTag("edit_server_host"),
                shape = RoundedCornerShape(12.dp)
            )

            OutlinedTextField(
                value = portText,
                onValueChange = { portText = it },
                label = { Text("Port") },
                modifier = Modifier.weight(1f).testTag("edit_server_port"),
                shape = RoundedCornerShape(12.dp)
            )
        }

        // SSH Specific Fields
        if (protocol == ProtocolType.SSH) {
            GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "SSH Credentials & Injector Settings",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.primary
                    )

                    OutlinedTextField(
                        value = sshUser,
                        onValueChange = { sshUser = it },
                        label = { Text("SSH Username") },
                        modifier = Modifier.fillMaxWidth().testTag("edit_ssh_user"),
                        shape = RoundedCornerShape(12.dp)
                    )

                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("SSH Password / Private Key") },
                        modifier = Modifier.fillMaxWidth().testTag("edit_ssh_password"),
                        shape = RoundedCornerShape(12.dp)
                    )

                    Text(
                        text = "Custom HTTP Injector Payload (Optional):",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    OutlinedTextField(
                        value = sshPayload,
                        onValueChange = { sshPayload = it },
                        placeholder = { Text("CONNECT [host_port] HTTP/1.1[crlf]Host: bug.isp.com[crlf]...") },
                        modifier = Modifier.fillMaxWidth().height(100.dp).testTag("edit_ssh_payload"),
                        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        shape = RoundedCornerShape(12.dp)
                    )

                    // Helper macro chips
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf("[host]", "[port]", "[host_port]", "[crlf]", "[protocol]", "[ua]").forEach { tag ->
                            AssistChip(
                                onClick = { sshPayload += tag },
                                label = { Text(tag) }
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        OutlinedTextField(
                            value = proxyHost,
                            onValueChange = { proxyHost = it },
                            label = { Text("Remote Proxy IP (Opt)") },
                            modifier = Modifier.weight(2f),
                            shape = RoundedCornerShape(12.dp)
                        )
                        OutlinedTextField(
                            value = proxyPortText,
                            onValueChange = { proxyPortText = it },
                            label = { Text("Proxy Port") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }
                }
            }
        } else {
            // Xray / V2Ray Fields
            GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "${protocol.displayName} Settings",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.primary
                    )

                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text(if (protocol == ProtocolType.VLESS || protocol == ProtocolType.VMESS) "UUID" else "Password") },
                        modifier = Modifier.fillMaxWidth().testTag("edit_xray_credential"),
                        shape = RoundedCornerShape(12.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        OutlinedTextField(
                            value = network,
                            onValueChange = { network = it },
                            label = { Text("Network (tcp/ws/grpc)") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp)
                        )
                        OutlinedTextField(
                            value = security,
                            onValueChange = { security = it },
                            label = { Text("Security (none/tls/reality)") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }

                    OutlinedTextField(
                        value = sni,
                        onValueChange = { sni = it },
                        label = { Text("SNI / ServerName") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    )

                    if (network.equals("ws", ignoreCase = true) || network.equals("grpc", ignoreCase = true)) {
                        OutlinedTextField(
                            value = path,
                            onValueChange = { path = it },
                            label = { Text("Path / Service Name") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }

                    if (security.equals("reality", ignoreCase = true)) {
                        OutlinedTextField(
                            value = pbk,
                            onValueChange = { pbk = it },
                            label = { Text("Reality Public Key (pbk)") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }
                }
            }
        }

        // Routing & Leak Settings
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "DNS & Leak Protections",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.onSurface
                )

                OutlinedTextField(
                    value = dnsPrimary,
                    onValueChange = { dnsPrimary = it },
                    label = { Text("Tunnel DNS Server") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Block IPv6 Leaks", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                        Text("Prevent traffic leaking outside tunnel", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(
                        checked = blockIpv6,
                        onCheckedChange = { blockIpv6 = it }
                    )
                }
            }
        }

        // Split Tunneling Card
        GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Per-App Split Tunneling", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                        Text("Route only selected applications through the VPN", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(
                        checked = perAppProxy,
                        onCheckedChange = { perAppProxy = it }
                    )
                }

                if (perAppProxy) {
                    OutlinedTextField(
                        value = selectedAppsText,
                        onValueChange = { selectedAppsText = it },
                        label = { Text("Allowed Packages (comma-separated)") },
                        placeholder = { Text("com.android.chrome, org.telegram.messenger") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    )

                    Text(
                        text = "Quick Presets:",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        listOf(
                            "Chrome" to "com.android.chrome",
                            "Firefox" to "org.mozilla.firefox",
                            "Telegram" to "org.telegram.messenger",
                            "WhatsApp" to "com.whatsapp"
                        ).forEach { (label, pkg) ->
                            AssistChip(
                                onClick = {
                                    val current = selectedAppsText.split(",")
                                        .map { it.trim() }
                                        .filter { it.isNotBlank() }
                                        .toMutableSet()
                                    current.add(pkg)
                                    selectedAppsText = current.joinToString(", ")
                                },
                                label = { Text(label) }
                            )
                        }
                    }
                }
            }
        }

        if (errorMessage != null) {
            Text(
                text = errorMessage ?: "",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        // Actions
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier.weight(1f).height(50.dp),
                shape = RoundedCornerShape(14.dp)
            ) {
                Text("Cancel")
            }

            Button(
                onClick = {
                    val port = portText.toIntOrNull()
                    if (server.isBlank()) {
                        errorMessage = "Server address cannot be empty"
                        return@Button
                    }
                    if (port == null || port !in 1..65535) {
                        errorMessage = "Port must be between 1 and 65535"
                        return@Button
                    }

                    val apps = if (perAppProxy) {
                        selectedAppsText.split(",").map { it.trim() }.filter { it.isNotBlank() }
                    } else {
                        emptyList()
                    }

                    val updated = (initialProfile ?: VpnProfile(
                        id = UUID.randomUUID().toString(),
                        name = name.ifBlank { "Tunnel-$server:$port" },
                        protocol = protocol,
                        server = server,
                        port = port
                    )).copy(
                        name = name.ifBlank { "Tunnel-$server:$port" },
                        protocol = protocol,
                        server = server,
                        port = port,
                        password = password,
                        security = security,
                        network = network,
                        sni = sni,
                        path = path,
                        publicKey = pbk,
                        sshUsername = sshUser,
                        sshPayload = sshPayload,
                        proxyHost = proxyHost,
                        proxyPort = proxyPortText.toIntOrNull() ?: 0,
                        dnsPrimary = dnsPrimary,
                        blockIpv6 = blockIpv6,
                        perAppProxy = perAppProxy,
                        selectedApps = apps
                    )

                    onSaveProfile(updated)
                },
                modifier = Modifier.weight(1f).height(50.dp).testTag("save_profile_button"),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = CyanPrimaryDark,
                    contentColor = Color(0xFF00363E)
                )
            ) {
                Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Save Profile", style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold))
            }
        }
    }
}
