package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.NetworkPing
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.draw.clip
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.parser.ConfigParser
import com.example.ui.components.GlassCard
import com.example.ui.theme.ConnectedGreen
import com.example.ui.theme.CyanPrimaryDark
import com.example.ui.theme.DisconnectedRed
import com.example.ui.theme.NeutralGrey
import com.example.ui.viewmodel.VpnViewModel

@Composable
fun ProfilesScreen(
    viewModel: VpnViewModel,
    onEditProfile: (VpnProfile) -> Unit,
    onCreateProfile: (ProtocolType) -> Unit,
    onNavigateToImport: () -> Unit,
    onExportProfile: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val profiles by viewModel.profiles.collectAsState()
    val selectedProfile by viewModel.selectedProfile.collectAsState()
    val pingingIds by viewModel.pingingProfileIds.collectAsState()

    var showCreateDialog by remember { mutableStateOf(false) }

    Box(modifier = modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            // Top action row: Count + Ping All + Import
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "VPN Profiles",
                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = "${profiles.size} configured tunnels",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    IconButton(
                        onClick = { viewModel.pingAllProfiles() },
                        modifier = Modifier.testTag("ping_all_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Test Latency All",
                            tint = CyanPrimaryDark
                        )
                    }

                    OutlinedButton(
                        onClick = onNavigateToImport,
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        modifier = Modifier.testTag("import_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.FileDownload,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Import")
                    }
                }
            }

            // Profiles list
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 80.dp)
            ) {
                items(profiles, key = { it.id }) { profile ->
                    val isSelected = selectedProfile?.id == profile.id
                    val isPinging = pingingIds.contains(profile.id)

                    ProfileItemCard(
                        profile = profile,
                        isSelected = isSelected,
                        isPinging = isPinging,
                        onSelect = { viewModel.selectProfile(profile) },
                        onPing = { viewModel.pingProfile(profile) },
                        onEdit = { onEditProfile(profile) },
                        onDuplicate = { viewModel.duplicateProfile(profile) },
                        onExport = {
                            val uri = ConfigParser.exportProfileToUri(profile)
                            onExportProfile(uri)
                        },
                        onDelete = { viewModel.deleteProfile(profile.id) }
                    )
                }
            }
        }

        // Add Profile FAB
        FloatingActionButton(
            onClick = { showCreateDialog = true },
            containerColor = CyanPrimaryDark,
            contentColor = Color(0xFF00363E),
            shape = CircleShape,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(24.dp)
                .testTag("add_profile_fab")
        ) {
            Icon(Icons.Default.Add, contentDescription = "Add Profile")
        }
    }

    if (showCreateDialog) {
        CreateProfileDialog(
            onDismiss = { showCreateDialog = false },
            onSelectProtocol = { protocol ->
                showCreateDialog = false
                onCreateProfile(protocol)
            },
            onSelectImport = {
                showCreateDialog = false
                onNavigateToImport()
            }
        )
    }
}

@Composable
fun ProfileItemCard(
    profile: VpnProfile,
    isSelected: Boolean,
    isPinging: Boolean,
    onSelect: () -> Unit,
    onPing: () -> Unit,
    onEdit: () -> Unit,
    onDuplicate: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit
) {
    var menuExpanded by remember { mutableStateOf(false) }

    GlassCard(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelect() }
            .testTag("profile_item_${profile.id}"),
        cornerRadius = 16.dp,
        borderColor = if (isSelected) CyanPrimaryDark else MaterialTheme.colorScheme.outline.copy(alpha = 0.2f)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.weight(1f)
            ) {
                // Protocol icon
                Surface(
                    shape = CircleShape,
                    color = Color(profile.protocol.badgeColorHex).copy(alpha = 0.2f),
                    modifier = Modifier.size(38.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        if (isSelected) {
                            Icon(
                                imageVector = Icons.Default.Check,
                                contentDescription = "Active",
                                tint = Color(profile.protocol.badgeColorHex),
                                modifier = Modifier.size(20.dp)
                            )
                        } else {
                            Icon(
                                imageVector = if (profile.protocol == ProtocolType.SSH) Icons.Default.Terminal else Icons.Default.Shield,
                                contentDescription = null,
                                tint = Color(profile.protocol.badgeColorHex),
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }

                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = profile.name,
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1
                        )
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = Color(profile.protocol.badgeColorHex).copy(alpha = 0.15f)
                        ) {
                            Text(
                                text = profile.protocol.displayName,
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                color = Color(profile.protocol.badgeColorHex),
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }

                        Text(
                            text = "${profile.server}:${profile.port}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                }
            }

            // Real Latency & Menu
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                // Real Latency pill
                Box(
                    modifier = Modifier
                        .clickable { onPing() }
                        .padding(4.dp)
                ) {
                    if (isPinging) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = CyanPrimaryDark
                        )
                    } else if (profile.lastPingMs != null) {
                        val ping = profile.lastPingMs
                        val (pingText, pingColor) = when {
                            ping < 0 -> "Fail" to DisconnectedRed
                            ping < 120 -> "${ping}ms" to ConnectedGreen
                            ping < 300 -> "${ping}ms" to Color(0xFFF59E0B)
                            else -> "${ping}ms" to DisconnectedRed
                        }
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = pingColor.copy(alpha = 0.15f)
                        ) {
                            Text(
                                text = pingText,
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                color = pingColor,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    } else {
                        Icon(
                            imageVector = Icons.Default.NetworkPing,
                            contentDescription = "Test Ping",
                            tint = NeutralGrey,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }

                // Options Menu
                Box {
                    IconButton(onClick = { menuExpanded = true }) {
                        Icon(Icons.Default.MoreVert, contentDescription = "Profile Options")
                    }

                    DropdownMenu(
                        expanded = menuExpanded,
                        onDismissRequest = { menuExpanded = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text("Use / Select") },
                            leadingIcon = { Icon(Icons.Default.Check, null) },
                            onClick = {
                                menuExpanded = false
                                onSelect()
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Edit Profile") },
                            leadingIcon = { Icon(Icons.Default.Edit, null) },
                            onClick = {
                                menuExpanded = false
                                onEdit()
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Duplicate") },
                            leadingIcon = { Icon(Icons.Default.ContentCopy, null) },
                            onClick = {
                                menuExpanded = false
                                onDuplicate()
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Export Config") },
                            leadingIcon = { Icon(Icons.Default.Share, null) },
                            onClick = {
                                menuExpanded = false
                                onExport()
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Delete", color = DisconnectedRed) },
                            leadingIcon = { Icon(Icons.Default.Delete, null, tint = DisconnectedRed) },
                            onClick = {
                                menuExpanded = false
                                onDelete()
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun CreateProfileDialog(
    onDismiss: () -> Unit,
    onSelectProtocol: (ProtocolType) -> Unit,
    onSelectImport: () -> Unit
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                "Create New Tunnel",
                style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold)
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Choose protocol engine or import configuration:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(4.dp))

                ProtocolOptionRow("VLESS (Xray Core)", ProtocolType.VLESS) { onSelectProtocol(ProtocolType.VLESS) }
                ProtocolOptionRow("VMess (Xray Core)", ProtocolType.VMESS) { onSelectProtocol(ProtocolType.VMESS) }
                ProtocolOptionRow("Trojan (TLS Secure)", ProtocolType.TROJAN) { onSelectProtocol(ProtocolType.TROJAN) }
                ProtocolOptionRow("SSH + HTTP Injector", ProtocolType.SSH) { onSelectProtocol(ProtocolType.SSH) }
                ProtocolOptionRow("Shadowsocks", ProtocolType.SHADOWSOCKS) { onSelectProtocol(ProtocolType.SHADOWSOCKS) }

                Spacer(modifier = Modifier.height(6.dp))
                OutlinedButton(
                    onClick = onSelectImport,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.FileDownload, null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Import from Clipboard or File")
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            androidx.compose.material3.TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun ProtocolOptionRow(
    title: String,
    protocol: ProtocolType,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.2f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(Color(protocol.badgeColorHex))
            )
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}
