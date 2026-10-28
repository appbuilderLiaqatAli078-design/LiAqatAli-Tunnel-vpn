package com.example.ui.viewmodel

import android.app.Application
import android.content.Context
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.AppLogger
import com.example.data.ProfileRepository
import com.example.data.SettingsRepository
import com.example.model.AppSettings
import com.example.model.LogEntry
import com.example.model.TrafficStats
import com.example.model.VpnProfile
import com.example.model.VpnState
import com.example.parser.ConfigParser
import com.example.parser.ParseResult
import com.example.vpn.CustomTunnelVpnService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class VpnViewModel(application: Application) : AndroidViewModel(application) {
    private val TAG = "VpnViewModel"
    private val profileRepository = ProfileRepository(application)
    private val settingsRepository = SettingsRepository(application)

    val vpnState: StateFlow<VpnState> = CustomTunnelVpnService.vpnState
    val trafficStats: StateFlow<TrafficStats> = CustomTunnelVpnService.trafficStats
    val profiles: StateFlow<List<VpnProfile>> = profileRepository.profiles
    val logs: StateFlow<List<LogEntry>> = AppLogger.logsFlow
    val settings: StateFlow<AppSettings> = settingsRepository.settings

    private val _selectedProfile = MutableStateFlow<VpnProfile?>(null)
    val selectedProfile: StateFlow<VpnProfile?> = _selectedProfile.asStateFlow()

    private val _pingingProfileIds = MutableStateFlow<Set<String>>(emptySet())
    val pingingProfileIds: StateFlow<Set<String>> = _pingingProfileIds.asStateFlow()

    init {
        viewModelScope.launch {
            profiles.collect { list ->
                if (list.isEmpty()) {
                    _selectedProfile.value = null
                    return@collect
                }

                // 1. Prefer currently active VPN service profile if tunnel is running,
                // 2. Otherwise use in-memory selection or persisted selectedProfileId from disk.
                val runningProfileId = if (vpnState.value.isConnected || vpnState.value.isBusy) {
                    CustomTunnelVpnService.activeProfile.value?.id
                } else null

                val targetId = runningProfileId
                    ?: _selectedProfile.value?.id
                    ?: profileRepository.getSelectedProfileId()

                val matched = targetId?.let { id -> list.find { it.id == id } } ?: list.first()
                _selectedProfile.value = matched
                profileRepository.setSelectedProfileId(matched.id)
                CustomTunnelVpnService.setActiveProfile(matched)
            }
        }
    }

    fun selectProfile(profile: VpnProfile) {
        _selectedProfile.value = profile
        profileRepository.setSelectedProfileId(profile.id)
        CustomTunnelVpnService.setActiveProfile(profile)
        AppLogger.i(TAG, "Selected profile: ${profile.name} (${profile.protocol.displayName})")
    }

    fun prepareVpnIntent(context: Context): android.content.Intent? {
        return VpnService.prepare(context)
    }

    fun connect(context: Context) {
        val profile = _selectedProfile.value ?: profiles.value.firstOrNull()
        if (profile == null) {
            AppLogger.e(TAG, "No profile available to connect")
            return
        }
        AppLogger.i(TAG, "User initiated connection to: ${profile.name}")
        CustomTunnelVpnService.startVpn(context, profile)
    }

    fun disconnect(context: Context) {
        AppLogger.i(TAG, "User requested disconnect")
        CustomTunnelVpnService.stopVpn(context)
    }

    fun saveProfile(profile: VpnProfile) {
        val isNewProfile = profiles.value.none { it.id == profile.id }
        profileRepository.saveProfile(profile)
        if (isNewProfile || _selectedProfile.value?.id == profile.id || _selectedProfile.value == null) {
            _selectedProfile.value = profile
            profileRepository.setSelectedProfileId(profile.id)
            CustomTunnelVpnService.setActiveProfile(profile)
        }
        AppLogger.i(TAG, "Saved profile: ${profile.name}")
    }

    fun deleteProfile(id: String) {
        profileRepository.deleteProfile(id)
        if (_selectedProfile.value?.id == id) {
            val next = profiles.value.firstOrNull { it.id != id }
            _selectedProfile.value = next
            profileRepository.setSelectedProfileId(next?.id)
            CustomTunnelVpnService.setActiveProfile(next)
        }
        AppLogger.i(TAG, "Deleted profile id: $id")
    }

    fun duplicateProfile(profile: VpnProfile) {
        if (profile.isLocked) {
            AppLogger.w(TAG, "Cannot duplicate locked .ctp profile: ${profile.name}")
            return
        }
        val dup = profileRepository.duplicateProfile(profile)
        AppLogger.i(TAG, "Duplicated profile: ${dup.name}")
    }

    fun importConfig(rawText: String, unlockPassword: String = ""): ParseResult {
        val result = ConfigParser.parse(rawText, unlockPassword, getApplication())
        if (result is ParseResult.Success) {
            saveProfile(result.profile)
            selectProfile(result.profile)
            AppLogger.i(TAG, "Successfully imported profile: ${result.profile.name}")
        } else if (result is ParseResult.Failure) {
            AppLogger.w(TAG, "Import failed: ${result.reason}")
        }
        return result
    }

    fun pingProfile(profile: VpnProfile) {
        viewModelScope.launch {
            _pingingProfileIds.value = _pingingProfileIds.value + profile.id
            profileRepository.pingProfile(profile)
            _pingingProfileIds.value = _pingingProfileIds.value - profile.id
        }
    }

    fun pingAllProfiles() {
        viewModelScope.launch {
            profiles.value.forEach { profile ->
                pingProfile(profile)
            }
        }
    }

    fun updateSettings(newSettings: AppSettings) {
        settingsRepository.updateSettings(newSettings)
    }

    fun clearLogs() {
        AppLogger.clear()
    }
}
