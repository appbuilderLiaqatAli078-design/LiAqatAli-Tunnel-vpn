package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.VpnProfile
import com.example.parser.ConfigParser
import com.example.parser.ParseResult
import com.example.security.CtpConfigCrypto
import com.example.security.DeviceSecurityManager
import com.example.ui.components.GlassCard
import com.example.ui.theme.ConnectedGreen
import com.example.ui.theme.CyanPrimaryDark
import com.example.ui.theme.DisconnectedRed
import com.example.ui.viewmodel.VpnViewModel

@Composable
fun ImportScreen(
    viewModel: VpnViewModel,
    onImportSuccess: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var inputText by remember { mutableStateOf("") }
    var unlockPassword by remember { mutableStateOf("") }
    var requiresPassword by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var isSuccess by remember { mutableStateOf(false) }
    var parsedProfile by remember { mutableStateOf<VpnProfile?>(null) }

    val deviceHwid = remember { DeviceSecurityManager.getHardwareId(context) }

    fun validateAndParse(text: String, password: String = unlockPassword) {
        val result = ConfigParser.parse(text, password, context)
        when (result) {
            is ParseResult.Success -> {
                isSuccess = true
                requiresPassword = false
                parsedProfile = result.profile
                statusMessage = if (result.profile.isLocked) {
                    "Valid encrypted .ctp configuration (Locked)"
                } else {
                    "Valid ${result.profile.protocol.displayName} configuration"
                }
            }
            is ParseResult.Failure -> {
                isSuccess = false
                parsedProfile = null
                requiresPassword = result.requiresPassword || CtpConfigCrypto.isCtpContent(text)
                statusMessage = result.reason
            }
        }
    }

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            try {
                context.contentResolver.openInputStream(uri)?.use { stream ->
                    val content = stream.bufferedReader().readText()
                    inputText = content
                    validateAndParse(content, unlockPassword)
                }
            } catch (e: Exception) {
                statusMessage = "Error reading .ctp file: ${e.message}"
                isSuccess = false
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Import .ctp Configuration",
            style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onBackground
        )

        Text(
            text = "Import encrypted Custom Tunnel Pro (.ctp) files, clipboard configs, or standard vmess://, vless://, trojan://, ss://, ssh://, or Xray JSON configurations.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // Device HWID Helper Card for HWID-locked .ctp files
        GlassCard(
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("Device HWID", deviceHwid))
                    Toast.makeText(context, "Copied HWID: $deviceHwid", Toast.LENGTH_SHORT).show()
                },
            cornerRadius = 12.dp
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Your Device Hardware ID (HWID)",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = deviceHwid,
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold
                        ),
                        color = CyanPrimaryDark
                    )
                }
                Icon(
                    imageVector = Icons.Default.ContentCopy,
                    contentDescription = "Copy HWID",
                    tint = CyanPrimaryDark,
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        // Actions: Clipboard + Choose .ctp File
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedButton(
                onClick = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = clipboard.primaryClip
                    if (clip != null && clip.itemCount > 0) {
                        val pasted = clip.getItemAt(0).text?.toString() ?: ""
                        inputText = pasted
                        validateAndParse(pasted, unlockPassword)
                    }
                },
                modifier = Modifier
                    .weight(1f)
                    .testTag("paste_clipboard_button")
            ) {
                Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Clipboard", maxLines = 1)
            }

            OutlinedButton(
                onClick = { filePickerLauncher.launch("*/*") },
                modifier = Modifier
                    .weight(1f)
                    .testTag("pick_file_button")
            ) {
                Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Choose .ctp File", maxLines = 1)
            }
        }

        // Password input if .ctp file requires an unlock password
        AnimatedVisibility(visible = requiresPassword || CtpConfigCrypto.isCtpContent(inputText)) {
            OutlinedTextField(
                value = unlockPassword,
                onValueChange = {
                    unlockPassword = it
                    if (inputText.isNotBlank()) {
                        validateAndParse(inputText, it)
                    }
                },
                label = { Text(".ctp Unlock Password (If Protected)") },
                leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null) },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("ctp_unlock_password_input"),
                shape = RoundedCornerShape(12.dp)
            )
        }

        // Configuration Text Area (masks raw content if it's an encrypted .ctp blob)
        OutlinedTextField(
            value = if (CtpConfigCrypto.isCtpContent(inputText)) "CTP2:[ENCRYPTED .CTP CONTAINER LOADED]" else inputText,
            onValueChange = {
                inputText = it
                if (it.isNotBlank()) {
                    validateAndParse(it, unlockPassword)
                } else {
                    statusMessage = null
                    parsedProfile = null
                }
            },
            label = { Text("Configuration (.ctp, URI, or JSON)") },
            placeholder = { Text("CTP2:..., vless://..., vmess://..., trojan://..., ssh://...") },
            modifier = Modifier
                .fillMaxWidth()
                .height(150.dp)
                .testTag("import_text_input"),
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            shape = RoundedCornerShape(16.dp),
            maxLines = 8
        )

        // Validation Result Banner (always masks server host outside Editor)
        AnimatedVisibility(visible = statusMessage != null) {
            GlassCard(
                modifier = Modifier.fillMaxWidth(),
                cornerRadius = 16.dp,
                borderColor = if (isSuccess) ConnectedGreen else DisconnectedRed
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = if (isSuccess) Icons.Default.CheckCircle else Icons.Default.ErrorOutline,
                        contentDescription = null,
                        tint = if (isSuccess) ConnectedGreen else DisconnectedRed,
                        modifier = Modifier.size(24.dp)
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = if (isSuccess) "Configuration Valid" else "Validation / Lock Status",
                            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                            color = if (isSuccess) ConnectedGreen else DisconnectedRed,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = statusMessage ?: "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (parsedProfile != null) {
                            Text(
                                text = "Endpoint: ${parsedProfile?.maskedEndpoint} (${parsedProfile?.protocol?.displayName})",
                                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.SemiBold),
                                color = MaterialTheme.colorScheme.primary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }
        }

        // Example Chips
        Text(
            text = "Supported Formats (.ctp, VMess, VLESS, Trojan, SSH):",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SuggestionChip(onClick = {
                inputText = "vmess://djp2bWVzc0BnZWVrc3Zwbi5rZXZpbnRlY2h0dXRvcmlhbHMuZnVuOjQ0Mz90eXBlPXdzJnBhdGg9L3ZtZXNzJnNlY3VyaXR5PXRscyZ1dWlkPWE0ODFjYzVlLTBlZGYtNDFiYy04NTQwLWM2ODRiMjYwMDk2Mg=="
                validateAndParse(inputText)
            }, label = { Text("VMess") })

            SuggestionChip(onClick = {
                inputText = "vless://d342d110-d4a3-4513-bfa6-07a5e0f0ff37@example.com:443?security=tls&type=ws&sni=example.com#VLESS-Demo"
                validateAndParse(inputText)
            }, label = { Text("VLESS") })

            SuggestionChip(onClick = {
                inputText = "trojan://password123@secure.vpn.org:443?sni=secure.vpn.org#Trojan-Demo"
                validateAndParse(inputText)
            }, label = { Text("Trojan") })

            SuggestionChip(onClick = {
                inputText = "ssh://root:secret@128.199.192.1:22#SSH-Demo"
                validateAndParse(inputText)
            }, label = { Text("SSH") })
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Save Button
        Button(
            onClick = {
                parsedProfile?.let { profile ->
                    viewModel.saveProfile(profile)
                    viewModel.selectProfile(profile)
                    onImportSuccess()
                }
            },
            enabled = isSuccess && parsedProfile != null,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp)
                .testTag("save_imported_button"),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = CyanPrimaryDark,
                contentColor = Color(0xFF00363E)
            )
        ) {
            Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("Save Profile", style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold))
        }
    }
}
