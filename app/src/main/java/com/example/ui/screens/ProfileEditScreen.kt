package com.example.ui.screens

import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Terminal
import com.example.parser.SshTargetParser
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
import com.example.model.SshTunnelMode
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
    var flow by remember { mutableStateOf(initialProfile?.flow ?: "") }

    // SSH Specific State
    var sshMode by remember { mutableStateOf(initialProfile?.sshMode ?: SshTunnelMode.DIRECT) }
    var sshAuthType by remember { mutableStateOf(if (initialProfile?.sshPrivateKey?.isNotBlank() == true) "key" else "password") }
    var sshUser by remember { mutableStateOf(initialProfile?.sshUsername ?: "root") }
    var sshPrivateKey by remember { mutableStateOf(initialProfile?.sshPrivateKey ?: "") }
    var sshPassphrase by remember { mutableStateOf(initialProfile?.sshPassphrase ?: "") }
    var sshPayload by remember { mutableStateOf(initialProfile?.sshPayload ?: "") }
    var proxyHost by remember { mutableStateOf(initialProfile?.proxyHost ?: "") }
    var proxyPortText by remember { mutableStateOf(initialProfile?.proxyPort?.let { if (it > 0) it.toString() else "" } ?: "") }
    var sshProxyUser by remember { mutableStateOf(initialProfile?.sshProxyUser ?: "") }
    var sshProxyPass by remember { mutableStateOf(initialProfile?.sshProxyPass ?: "") }
    var sshSni by remember { mutableStateOf(initialProfile?.sshSni ?: "") }
    var sshWsPath by remember { mutableStateOf(initialProfile?.sshWsPath ?: "/ssh") }
    var sshCustomHeaders by remember { mutableStateOf(initialProfile?.sshCustomHeaders ?: "") }
    var sshChainProxyHost by remember { mutableStateOf(initialProfile?.sshChainProxyHost ?: "") }
    var sshChainProxyPortText by remember { mutableStateOf(initialProfile?.sshChainProxyPort?.let { if (it > 0) it.toString() else "" } ?: "") }
    var sshChainProxyType by remember { mutableStateOf(initialProfile?.sshChainProxyType ?: "SOCKS5") }
    var sshLocalForwardPortText by remember { mutableStateOf(initialProfile?.sshLocalForwardPort?.toString() ?: "10880") }
    var sshRemoteForwardHost by remember { mutableStateOf(initialProfile?.sshRemoteForwardHost ?: "127.0.0.1") }
    var sshRemoteForwardPortText by remember { mutableStateOf(initialProfile?.sshRemoteForwardPort?.toString() ?: "80") }
    var sshRemoteListenPortText by remember { mutableStateOf(initialProfile?.sshRemoteListenPort?.toString() ?: "8080") }
    var allowInsecureSsl by remember { mutableStateOf(initialProfile?.allowInsecureSsl ?: false) }

    // DNS & IPv6
    var dnsPrimary by remember { mutableStateOf(initialProfile?.dnsPrimary ?: "1.1.1.1") }
    var blockIpv6 by remember { mutableStateOf(initialProfile?.blockIpv6 ?: true) }
    var perAppProxy by remember { mutableStateOf(initialProfile?.perAppProxy ?: false) }
    var selectedAppsText by remember { mutableStateOf(initialProfile?.selectedApps?.joinToString(", ") ?: "") }

    var errorMessage by remember { mutableStateOf<String?>(null) }

    var isSessionUnlocked by remember { mutableStateOf(initialProfile?.isLocked != true) }
    var unlockInput by remember { mutableStateOf("") }
    var unlockError by remember { mutableStateOf<String?>(null) }

    if (!isSessionUnlocked && initialProfile != null) {
        Column(
            modifier = modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = Icons.Default.Lock,
                contentDescription = "Locked .ctp",
                tint = CyanPrimaryDark,
                modifier = Modifier.size(56.dp)
            )
            Text(
                text = "Locked .ctp Configuration",
                style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onBackground
            )
            Text(
                text = "Server host (${initialProfile.maskedEndpoint}), credentials, and payload are encrypted and hidden by the configuration creator.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (initialProfile.lockPasswordHash.isNotBlank()) {
                OutlinedTextField(
                    value = unlockInput,
                    onValueChange = {
                        unlockInput = it
                        unlockError = null
                    },
                    label = { Text("Enter Creator Unlock Password") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                if (unlockError != null) {
                    Text(
                        text = unlockError!!,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                Button(
                    onClick = {
                        if (com.example.security.CtpConfigCrypto.verifyUnlockPassword(unlockInput, initialProfile.lockPasswordHash)) {
                            isSessionUnlocked = true
                        } else {
                            unlockError = "Incorrect unlock password"
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Unlock Editor")
                }
            }
            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Back to Profiles")
            }
        }
        return
    }

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

        // Protocol Selector
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
            label = { Text("Profile Name", maxLines = 1) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("edit_profile_name"),
            shape = RoundedCornerShape(12.dp)
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedTextField(
                value = server,
                onValueChange = { input ->
                    if (protocol == ProtocolType.SSH && (input.contains("@") || input.startsWith("ssh://") || input.contains(":"))) {
                        val parsed = SshTargetParser.parse(input)
                        if (parsed != null) {
                            server = parsed.host
                            portText = parsed.port.toString()
                            if (parsed.username.isNotBlank()) sshUser = parsed.username
                            if (parsed.password.isNotBlank()) password = parsed.password
                            if (name.isBlank() || name == "New Profile" || name == "Custom Profile") {
                                name = parsed.name ?: "SSH-${parsed.host}:${parsed.port}"
                            }
                        } else {
                            server = input
                        }
                    } else {
                        server = input
                    }
                },
                label = { Text("Server Host / Target", maxLines = 1) },
                placeholder = { Text("e.g. host:port@user:pass", maxLines = 1) },
                singleLine = true,
                modifier = Modifier.weight(1f).testTag("edit_server_host"),
                shape = RoundedCornerShape(12.dp)
            )

            OutlinedTextField(
                value = portText,
                onValueChange = { portText = it },
                label = { Text("Port", maxLines = 1) },
                singleLine = true,
                modifier = Modifier.width(96.dp).testTag("edit_server_port"),
                shape = RoundedCornerShape(12.dp)
            )
        }

        // SSH Specific Configuration
        if (protocol == ProtocolType.SSH) {
            // SSH Mode Selector
            GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "SSH Tunnel Mode",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = sshMode.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        SshTunnelMode.values().forEach { mode ->
                            FilterChip(
                                selected = sshMode == mode,
                                onClick = { sshMode = mode },
                                label = {
                                    Text(
                                        text = "${mode.badge}  ${mode.displayName}",
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                }
                            )
                        }
                    }
                }
            }

            // SSH Credentials Card
            GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "SSH Authentication",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.primary
                    )

                    OutlinedTextField(
                        value = sshUser,
                        onValueChange = { sshUser = it },
                        label = { Text("SSH Username", maxLines = 1) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("edit_ssh_user"),
                        shape = RoundedCornerShape(12.dp)
                    )

                    // Auth Type Toggle
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        FilterChip(
                            selected = sshAuthType == "password",
                            onClick = { sshAuthType = "password" },
                            label = { Text("Password Auth") },
                            leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp)) },
                            modifier = Modifier.weight(1f)
                        )
                        FilterChip(
                            selected = sshAuthType == "key",
                            onClick = { sshAuthType = "key" },
                            label = { Text("Private Key Auth") },
                            leadingIcon = { Icon(Icons.Default.Key, contentDescription = null, modifier = Modifier.size(16.dp)) },
                            modifier = Modifier.weight(1f)
                        )
                    }

                    if (sshAuthType == "password") {
                        OutlinedTextField(
                            value = password,
                            onValueChange = { password = it },
                            label = { Text("SSH Password", maxLines = 1) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth().testTag("edit_ssh_password"),
                            shape = RoundedCornerShape(12.dp)
                        )
                    } else {
                        OutlinedTextField(
                            value = sshPrivateKey,
                            onValueChange = { sshPrivateKey = it },
                            label = { Text("Private Key (PEM / OpenSSH format)") },
                            placeholder = { Text("-----BEGIN OPENSSH PRIVATE KEY-----\n...") },
                            modifier = Modifier.fillMaxWidth().height(120.dp),
                            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            shape = RoundedCornerShape(12.dp)
                        )

                        OutlinedTextField(
                            value = sshPassphrase,
                            onValueChange = { sshPassphrase = it },
                            label = { Text("Key Passphrase (optional)") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }
                }
            }

            // Mode-Specific Transport Settings Card
            GlassCard(modifier = Modifier.fillMaxWidth(), cornerRadius = 16.dp) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "${sshMode.displayName} Settings",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.primary
                    )

                    when (sshMode) {
                        SshTunnelMode.DIRECT -> {
                            Text(
                                text = "Direct SSH server connection with optional custom injector payload (e.g. WebSocket / HTTP payload).",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            OutlinedTextField(
                                value = sshPayload,
                                onValueChange = { sshPayload = it },
                                label = { Text("Custom HTTP / WebSocket Payload (Optional)") },
                                placeholder = { Text("GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]") },
                                modifier = Modifier.fillMaxWidth().height(120.dp).testTag("edit_ssh_payload_direct"),
                                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                shape = RoundedCornerShape(12.dp)
                            )
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                listOf("[crlf]", "[host]", "[port]", "[host_port]", "[method]", "[protocol]", "[ua]", "[split]").forEach { tag ->
                                    AssistChip(
                                        onClick = { sshPayload += tag },
                                        label = { Text(tag) }
                                    )
                                }
                            }
                        }

                        SshTunnelMode.HTTP_PROXY, SshTunnelMode.HTTP_CONNECT -> {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = proxyHost,
                                    onValueChange = { proxyHost = it },
                                    label = { Text("HTTP Proxy Host") },
                                    modifier = Modifier.weight(2f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = proxyPortText,
                                    onValueChange = { proxyPortText = it },
                                    label = { Text("Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = sshProxyUser,
                                    onValueChange = { sshProxyUser = it },
                                    label = { Text("Proxy User (Opt)") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = sshProxyPass,
                                    onValueChange = { sshProxyPass = it },
                                    label = { Text("Proxy Pass (Opt)") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                            OutlinedTextField(
                                value = sshCustomHeaders,
                                onValueChange = { sshCustomHeaders = it },
                                label = { Text("Custom HTTP Headers (Header: Value per line)") },
                                placeholder = { Text("X-Online-Host: bug.isp.com\nX-Forward-Host: bug.isp.com") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                        }

                        SshTunnelMode.CUSTOM_PAYLOAD -> {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = proxyHost,
                                    onValueChange = { proxyHost = it },
                                    label = { Text("Remote Proxy Host (Opt)") },
                                    modifier = Modifier.weight(2f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = proxyPortText,
                                    onValueChange = { proxyPortText = it },
                                    label = { Text("Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                            OutlinedTextField(
                                value = sshPayload,
                                onValueChange = { sshPayload = it },
                                label = { Text("Custom HTTP Injector Payload") },
                                placeholder = { Text("CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf]...") },
                                modifier = Modifier.fillMaxWidth().height(100.dp).testTag("edit_ssh_payload"),
                                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                shape = RoundedCornerShape(12.dp)
                            )
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                listOf("[host]", "[port]", "[host_port]", "[method]", "[protocol]", "[crlf]", "[auth]", "[split]", "[ua]", "[reverse_proxy]").forEach { tag ->
                                    AssistChip(
                                        onClick = { sshPayload += tag },
                                        label = { Text(tag) }
                                    )
                                }
                            }
                        }

                        SshTunnelMode.SSL_TLS -> {
                            OutlinedTextField(
                                value = sshSni,
                                onValueChange = { sshSni = it },
                                label = { Text("TLS SNI / ServerName (e.g. cloudflare.com)") },
                                placeholder = { Text(server.ifBlank { "example.com" }) },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Allow Insecure SSL Certificates", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                                    Text("Permit self-signed certificates without verification", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                Switch(checked = allowInsecureSsl, onCheckedChange = { allowInsecureSsl = it })
                            }
                        }

                        SshTunnelMode.WEBSOCKET -> {
                            OutlinedTextField(
                                value = sshWsPath,
                                onValueChange = { sshWsPath = it },
                                label = { Text("WebSocket Path (e.g. /ssh or /ws)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                            OutlinedTextField(
                                value = sshCustomHeaders,
                                onValueChange = { sshCustomHeaders = it },
                                label = { Text("Extra WebSocket Headers (Header: Value per line)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                        }

                        SshTunnelMode.SECURE_WEBSOCKET, SshTunnelMode.SSL_WEBSOCKET -> {
                            OutlinedTextField(
                                value = sshSni,
                                onValueChange = { sshSni = it },
                                label = { Text("TLS SNI Host (e.g. cdn.domain.com)") },
                                placeholder = { Text(server.ifBlank { "example.com" }) },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                            OutlinedTextField(
                                value = sshWsPath,
                                onValueChange = { sshWsPath = it },
                                label = { Text("WebSocket Path (e.g. /ssh or /ws)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                            OutlinedTextField(
                                value = sshCustomHeaders,
                                onValueChange = { sshCustomHeaders = it },
                                label = { Text("Custom Headers (Header: Value)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Allow Insecure SSL Certificates", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                                    Text("Permit self-signed or unverified SSL chains", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                Switch(checked = allowInsecureSsl, onCheckedChange = { allowInsecureSsl = it })
                            }
                        }

                        SshTunnelMode.SOCKS4 -> {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = proxyHost,
                                    onValueChange = { proxyHost = it },
                                    label = { Text("SOCKS4 Proxy Host") },
                                    modifier = Modifier.weight(2f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = proxyPortText,
                                    onValueChange = { proxyPortText = it },
                                    label = { Text("Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                            OutlinedTextField(
                                value = sshProxyUser,
                                onValueChange = { sshProxyUser = it },
                                label = { Text("User ID (e.g. aegis)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                        }

                        SshTunnelMode.SOCKS5 -> {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = proxyHost,
                                    onValueChange = { proxyHost = it },
                                    label = { Text("SOCKS5 Proxy Host") },
                                    modifier = Modifier.weight(2f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = proxyPortText,
                                    onValueChange = { proxyPortText = it },
                                    label = { Text("Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = sshProxyUser,
                                    onValueChange = { sshProxyUser = it },
                                    label = { Text("Username (Optional)") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = sshProxyPass,
                                    onValueChange = { sshProxyPass = it },
                                    label = { Text("Password (Optional)") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                        }

                        SshTunnelMode.PROXY_CHAIN -> {
                            Text(
                                text = "Hop 1 Proxy (Initial entry node)",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = proxyHost,
                                    onValueChange = { proxyHost = it },
                                    label = { Text("Hop 1 Host") },
                                    modifier = Modifier.weight(2f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = proxyPortText,
                                    onValueChange = { proxyPortText = it },
                                    label = { Text("Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                            Text(
                                text = "Hop 2 Proxy (Intermediary node)",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = sshChainProxyHost,
                                    onValueChange = { sshChainProxyHost = it },
                                    label = { Text("Hop 2 Host") },
                                    modifier = Modifier.weight(2f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = sshChainProxyPortText,
                                    onValueChange = { sshChainProxyPortText = it },
                                    label = { Text("Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                        }

                        SshTunnelMode.LOCAL_PORT_FORWARDING -> {
                            Text(
                                text = "Binds local port on device and forwards TCP connections over SSH direct-tcpip to remote destination.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = sshLocalForwardPortText,
                                    onValueChange = { sshLocalForwardPortText = it },
                                    label = { Text("Local Bound Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = sshRemoteForwardPortText,
                                    onValueChange = { sshRemoteForwardPortText = it },
                                    label = { Text("Remote Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                            OutlinedTextField(
                                value = sshRemoteForwardHost,
                                onValueChange = { sshRemoteForwardHost = it },
                                label = { Text("Remote Target Host (e.g. 127.0.0.1)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                        }

                        SshTunnelMode.REMOTE_PORT_FORWARDING -> {
                            Text(
                                text = "Requests remote SSH server to bind a listening port and reverse-forward incoming connections to local device target.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedTextField(
                                    value = sshRemoteListenPortText,
                                    onValueChange = { sshRemoteListenPortText = it },
                                    label = { Text("Remote Server Listen Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                OutlinedTextField(
                                    value = sshRemoteForwardPortText,
                                    onValueChange = { sshRemoteForwardPortText = it },
                                    label = { Text("Local Port") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                            }
                            OutlinedTextField(
                                value = sshRemoteForwardHost,
                                onValueChange = { sshRemoteForwardHost = it },
                                label = { Text("Local Target Host (e.g. 127.0.0.1)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            )
                        }

                        SshTunnelMode.DYNAMIC_PORT_FORWARDING -> {
                            Text(
                                text = "Dynamic SOCKS5 proxy running on 127.0.0.1:10809. Routes all device and application TCP traffic through SSH multiplexed direct-tcpip channels.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
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

                    if (protocol == ProtocolType.VLESS) {
                        OutlinedTextField(
                            value = flow,
                            onValueChange = { flow = it },
                            label = { Text("Flow (e.g. xtls-rprx-vision)") },
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
                    val targetInfo = if (protocol == ProtocolType.SSH && (server.contains("@") || server.startsWith("ssh://") || server.contains(":"))) {
                        SshTargetParser.parse(server, portText.toIntOrNull() ?: 22)
                    } else null

                    val effectiveServer = targetInfo?.host ?: server
                    val effectivePort = targetInfo?.port ?: portText.toIntOrNull()
                    val effectiveUser = if (sshUser.isNotBlank() && sshUser != "root") sshUser else (targetInfo?.username?.ifBlank { "root" } ?: sshUser)
                    val effectivePass = if (password.isNotBlank()) password else (targetInfo?.password ?: "")

                    if (effectiveServer.isBlank()) {
                        errorMessage = "Server address cannot be empty"
                        return@Button
                    }
                    if (effectivePort == null || effectivePort !in 1..65535) {
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
                        name = name.ifBlank { "Tunnel-$effectiveServer:$effectivePort" },
                        protocol = protocol,
                        server = effectiveServer,
                        port = effectivePort
                    )).copy(
                        name = name.ifBlank { "Tunnel-$effectiveServer:$effectivePort" },
                        protocol = protocol,
                        server = effectiveServer,
                        port = effectivePort,
                        password = effectivePass,
                        security = security,
                        network = network,
                        sni = sni,
                        path = path,
                        publicKey = pbk,
                        sshUsername = effectiveUser,
                        sshPayload = sshPayload,
                        proxyHost = proxyHost,
                        proxyPort = proxyPortText.toIntOrNull() ?: 0,
                        dnsPrimary = dnsPrimary,
                        blockIpv6 = blockIpv6,
                        perAppProxy = perAppProxy,
                        selectedApps = apps,
                        flow = flow.trim(),
                        sshMode = sshMode,
                        sshPrivateKey = if (sshAuthType == "key") sshPrivateKey.trim() else "",
                        sshPassphrase = sshPassphrase,
                        sshProxyUser = sshProxyUser.trim(),
                        sshProxyPass = sshProxyPass,
                        sshSni = sshSni.trim(),
                        sshWsPath = sshWsPath.trim(),
                        sshCustomHeaders = sshCustomHeaders.trim(),
                        sshChainProxyHost = sshChainProxyHost.trim(),
                        sshChainProxyPort = sshChainProxyPortText.toIntOrNull() ?: 0,
                        sshChainProxyType = sshChainProxyType,
                        sshLocalForwardPort = sshLocalForwardPortText.toIntOrNull() ?: 10880,
                        sshRemoteForwardHost = sshRemoteForwardHost.trim().ifBlank { "127.0.0.1" },
                        sshRemoteForwardPort = sshRemoteForwardPortText.toIntOrNull() ?: 80,
                        sshRemoteListenPort = sshRemoteListenPortText.toIntOrNull() ?: 8080,
                        allowInsecureSsl = allowInsecureSsl
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
