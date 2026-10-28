package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.NetworkPing
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.parser.ConfigParser
import com.example.security.CtpConfigCrypto
import com.example.security.CtpExportOptions
import com.example.security.DeviceSecurityManager
import com.example.ui.components.GlassCard
import com.example.ui.theme.ConnectedGreen
import com.example.ui.theme.CyanPrimaryDark
import com.example.ui.theme.DisconnectedRed
import com.example.ui.theme.NeutralGrey
import com.example.ui.viewmodel.VpnViewModel
import java.nio.charset.StandardCharsets

@Composable
fun ProfilesScreen(
    viewModel: VpnViewModel,
    onEditProfile: (VpnProfile) -> Unit,
    onCreateProfile: (ProtocolType) -> Unit,
    onNavigateToImport: () -> Unit,
    onExportProfile: (String, String?) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val profiles by viewModel.profiles.collectAsState()
    val selectedProfile by viewModel.selectedProfile.collectAsState()
    val pingingIds by viewModel.pingingProfileIds.collectAsState()

    var showCreateDialog by remember { mutableStateOf(false) }
    var exportingProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var pendingCtpSaveContent by remember { mutableStateOf<String?>(null) }
    var unlockingProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var lockedNoticeProfile by remember { mutableStateOf<VpnProfile?>(null) }

    val deviceHwid = remember { DeviceSecurityManager.getHardwareId(context) }

    val saveCtpFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val content = pendingCtpSaveContent
        if (uri != null && content != null) {
            try {
                context.contentResolver.openOutputStream(uri)?.use { out ->
                    out.write(content.toByteArray(StandardCharsets.UTF_8))
                }
                Toast.makeText(context, "Saved encrypted .ctp file successfully", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(context, "Failed to save .ctp file: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
        pendingCtpSaveContent = null
    }

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
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "VPN Profiles",
                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = "${profiles.size} configured tunnels • HWID: $deviceHwid",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.clickable {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("Device HWID", deviceHwid))
                            Toast.makeText(context, "Copied HWID: $deviceHwid", Toast.LENGTH_SHORT).show()
                        }
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
                        Text("Import .ctp")
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
                        onEdit = {
                            if (!profile.isLocked) {
                                onEditProfile(profile)
                            } else if (profile.lockPasswordHash.isNotBlank()) {
                                unlockingProfile = profile
                            } else {
                                lockedNoticeProfile = profile
                            }
                        },
                        onDuplicate = {
                            if (profile.isLocked) {
                                Toast.makeText(context, "Locked .ctp profile cannot be duplicated", Toast.LENGTH_SHORT).show()
                            } else {
                                viewModel.duplicateProfile(profile)
                            }
                        },
                        onExport = {
                            exportingProfile = profile
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

    exportingProfile?.let { profile ->
        CtpExportDialog(
            profile = profile,
            deviceHwid = deviceHwid,
            onDismiss = { exportingProfile = null },
            onShareOrCopy = { content, fileName ->
                exportingProfile = null
                onExportProfile(content, fileName)
            },
            onSaveToFile = { content, fileName ->
                exportingProfile = null
                pendingCtpSaveContent = content
                saveCtpFileLauncher.launch(fileName)
            }
        )
    }

    unlockingProfile?.let { profile ->
        UnlockProfileDialog(
            profile = profile,
            onDismiss = { unlockingProfile = null },
            onUnlocked = {
                unlockingProfile = null
                onEditProfile(profile.copy(isLocked = false))
            }
        )
    }

    lockedNoticeProfile?.let { profile ->
        AlertDialog(
            onDismissRequest = { lockedNoticeProfile = null },
            title = {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = CyanPrimaryDark)
                    Text("Locked .ctp Configuration", style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold))
                }
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "\"${profile.name}\" is an encrypted .ctp configuration locked by its creator.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        "Server host, credentials, and custom payloads are protected and cannot be viewed or edited in the Editor.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (profile.creatorMessage.isNotBlank()) {
                        Text(
                            "Creator Note: ${profile.creatorMessage}",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { lockedNoticeProfile = null }) {
                    Text("OK")
                }
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
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (profile.isLocked) {
                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = "Locked .ctp",
                                tint = CyanPrimaryDark,
                                modifier = Modifier.size(14.dp)
                            )
                        }
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
                                text = if (profile.protocol == ProtocolType.SSH) "SSH • ${profile.sshMode.badge}" else profile.protocol.displayName,
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                color = Color(profile.protocol.badgeColorHex),
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }

                        // Always mask host as dots outside the Editor
                        Text(
                            text = profile.maskedEndpoint,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false).testTag("profile_masked_host_${profile.id}")
                        )
                    }

                    if (profile.creatorMessage.isNotBlank()) {
                        Text(
                            text = profile.creatorMessage,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
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
                            text = { Text(if (profile.isLocked) "Unlock / View" else "Edit Profile") },
                            leadingIcon = { Icon(if (profile.isLocked) Icons.Default.Lock else Icons.Default.Edit, null) },
                            onClick = {
                                menuExpanded = false
                                onEdit()
                            }
                        )
                        if (!profile.isLocked) {
                            DropdownMenuItem(
                                text = { Text("Duplicate") },
                                leadingIcon = { Icon(Icons.Default.ContentCopy, null) },
                                onClick = {
                                    menuExpanded = false
                                    onDuplicate()
                                }
                            )
                        }
                        DropdownMenuItem(
                            text = { Text("Export .ctp Config") },
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
fun CtpExportDialog(
    profile: VpnProfile,
    deviceHwid: String,
    onDismiss: () -> Unit,
    onShareOrCopy: (String, String?) -> Unit,
    onSaveToFile: (String, String) -> Unit
) {
    var lockConfig by remember { mutableStateOf(true) }
    var expiryDays by remember { mutableIntStateOf(0) } // 0 = Never, 1 = 24h, 3 = 3d, 7 = 7d, 30 = 30d
    var unlockPassword by remember { mutableStateOf("") }
    var requirePasswordOnImport by remember { mutableStateOf(false) }
    var lockedHwid by remember { mutableStateOf("") }
    var blockRoot by remember { mutableStateOf(true) }
    var creatorMessage by remember { mutableStateOf(profile.creatorMessage) }

    val sanitizedFileName = remember(profile.name) {
        val base = profile.name.replace(Regex("[^a-zA-Z0-9._-]"), "_").ifBlank { "config" }
        "$base.${CtpConfigCrypto.CTP_FILE_EXTENSION}"
    }

    fun buildExportContent(): String {
        val expiresAt = if (expiryDays > 0) {
            System.currentTimeMillis() + expiryDays * 24L * 60L * 60L * 1000L
        } else 0L
        return ConfigParser.exportProfileToCtp(
            profile = profile,
            options = CtpExportOptions(
                lockConfig = lockConfig,
                expiresAtMillis = expiresAt,
                unlockPassword = unlockPassword.trim(),
                requirePasswordOnImport = requirePasswordOnImport,
                lockedHwid = lockedHwid.trim(),
                blockRoot = blockRoot,
                creatorMessage = creatorMessage.trim()
            )
        )
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(Icons.Default.Lock, contentDescription = null, tint = CyanPrimaryDark)
                Text(
                    "Export .ctp Config",
                    style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold)
                )
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "File: $sanitizedFileName (AES-256-GCM Encrypted)",
                    style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                    color = CyanPrimaryDark
                )

                // 1. Lock Config in Editor
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Lock Config in Editor", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                        Text("Hide host, credentials & payload from recipients", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(
                        checked = lockConfig,
                        onCheckedChange = { if (!profile.isLocked) lockConfig = it },
                        enabled = !profile.isLocked
                    )
                }

                // 2. Block Rooted Devices
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Block Rooted Devices", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold))
                        Text("Prevent import & connection on rooted phones", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(
                        checked = blockRoot,
                        onCheckedChange = { blockRoot = it }
                    )
                }

                // 3. Expiration Date
                Text(
                    text = "Expiration Lock",
                    style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.primary
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    listOf(
                        0 to "No Expiry",
                        1 to "24 Hours",
                        3 to "3 Days",
                        7 to "7 Days",
                        30 to "30 Days"
                    ).forEach { (days, label) ->
                        FilterChip(
                            selected = expiryDays == days,
                            onClick = { expiryDays = days },
                            label = { Text(label, style = MaterialTheme.typography.labelSmall) }
                        )
                    }
                }

                // 4. Optional Unlock / Import Password
                OutlinedTextField(
                    value = unlockPassword,
                    onValueChange = { unlockPassword = it },
                    label = { Text("Unlock Password (Optional)", maxLines = 1) },
                    placeholder = { Text("Leave blank for no password", maxLines = 1) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                if (unlockPassword.isNotBlank()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Require password on Import",
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.weight(1f)
                        )
                        Switch(
                            checked = requirePasswordOnImport,
                            onCheckedChange = { requirePasswordOnImport = it }
                        )
                    }
                }

                // 5. Hardware ID (HWID) Lock
                OutlinedTextField(
                    value = lockedHwid,
                    onValueChange = { lockedHwid = it },
                    label = { Text("Lock to Hardware ID (Optional)", maxLines = 1) },
                    placeholder = { Text("e.g. $deviceHwid", maxLines = 1) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                // 6. Creator Note / Message
                OutlinedTextField(
                    value = creatorMessage,
                    onValueChange = { creatorMessage = it },
                    label = { Text("Creator Note / Banner (Optional)", maxLines = 1) },
                    placeholder = { Text("e.g. Custom Tunnel Pro • @LiaqatAliPro", maxLines = 1) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val ctp = buildExportContent()
                            onSaveToFile(ctp, sanitizedFileName)
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Save, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Save .ctp", maxLines = 1)
                    }

                    Button(
                        onClick = {
                            val ctp = buildExportContent()
                            onShareOrCopy(ctp, sanitizedFileName)
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyanPrimaryDark,
                            contentColor = Color(0xFF00363E)
                        ),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Share, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Share .ctp", maxLines = 1)
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun UnlockProfileDialog(
    profile: VpnProfile,
    onDismiss: () -> Unit,
    onUnlocked: () -> Unit
) {
    var password by remember { mutableStateOf("") }
    var errorText by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                "Unlock .ctp Profile",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Enter the creator's unlock password to view and edit \"${profile.name}\" in the Editor:",
                    style = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = {
                        password = it
                        errorText = null
                    },
                    label = { Text("Unlock Password") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                if (errorText != null) {
                    Text(
                        text = errorText!!,
                        style = MaterialTheme.typography.labelSmall,
                        color = DisconnectedRed
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (CtpConfigCrypto.verifyUnlockPassword(password, profile.lockPasswordHash)) {
                        onUnlocked()
                    } else {
                        errorText = "Invalid unlock password"
                    }
                }
            ) {
                Text("Unlock")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun CreateProfileDialog(
    onDismiss: () -> Unit,
    onSelectProtocol: (ProtocolType) -> Unit,
    onSelectImport: () -> Unit
) {
    AlertDialog(
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
                    "Choose protocol engine or import .ctp configuration:",
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
                    Text("Import .ctp File or Clipboard")
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
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
