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
import com.example.vpn.AegisVpnService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class VpnViewModel(application: Application) : AndroidViewModel(application) {
    private val TAG = "VpnViewModel"
    private val profileRepository = ProfileRepository(application)
    private val settingsRepository = SettingsRepository(application)

    val vpnState: StateFlow<VpnState> = AegisVpnService.vpnState
    val trafficStats: StateFlow<TrafficStats> = AegisVpnService.trafficStats
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
                if (_selectedProfile.value == null && list.isNotEmpty()) {
                    _selectedProfile.value = list.first()
                    AegisVpnService.setActiveProfile(list.first())
                }
            }
        }
    }

    fun selectProfile(profile: VpnProfile) {
        _selectedProfile.value = profile
        AegisVpnService.setActiveProfile(profile)
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
        AegisVpnService.startVpn(context, profile)
    }

    fun disconnect(context: Context) {
        AppLogger.i(TAG, "User requested disconnect")
        AegisVpnService.stopVpn(context)
    }

    fun saveProfile(profile: VpnProfile) {
        profileRepository.saveProfile(profile)
        if (_selectedProfile.value?.id == profile.id || _selectedProfile.value == null) {
            _selectedProfile.value = profile
            AegisVpnService.setActiveProfile(profile)
        }
        AppLogger.i(TAG, "Saved profile: ${profile.name}")
    }

    fun deleteProfile(id: String) {
        profileRepository.deleteProfile(id)
        if (_selectedProfile.value?.id == id) {
            _selectedProfile.value = profiles.value.firstOrNull { it.id != id }
            AegisVpnService.setActiveProfile(_selectedProfile.value)
        }
        AppLogger.i(TAG, "Deleted profile id: $id")
    }

    fun duplicateProfile(profile: VpnProfile) {
        val dup = profileRepository.duplicateProfile(profile)
        AppLogger.i(TAG, "Duplicated profile: ${dup.name}")
    }

    fun importConfig(rawText: String): ParseResult {
        val result = ConfigParser.parse(rawText)
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
