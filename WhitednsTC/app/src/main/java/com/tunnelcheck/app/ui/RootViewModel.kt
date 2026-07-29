package com.tunnelcheck.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tunnelcheck.app.data.export.EndpointParser
import com.tunnelcheck.app.data.export.ResultExporter
import com.tunnelcheck.app.domain.model.EndpointInput
import com.tunnelcheck.app.domain.model.EndpointResult
import com.tunnelcheck.app.domain.model.ResultFilter
import com.tunnelcheck.app.domain.model.ScanMode
import com.tunnelcheck.app.domain.model.ScanOptions
import com.tunnelcheck.app.domain.repo.ScanRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

data class RootUiState(
    val filter: ResultFilter = ResultFilter.All,
    val results: List<EndpointResult> = emptyList(),
    val quickResults: List<EndpointResult> = emptyList(),
    val bulkResults: List<EndpointResult> = emptyList(),
    val settings: AppSettings = AppSettings(),
    val text: AppText = appText(AppLanguage.English),
    val activeScan: Boolean = false,
    val progressText: String = "",
    val error: String? = null,
    val exportText: String = ""
)

@HiltViewModel
class RootViewModel @Inject constructor(
    private val repository: ScanRepository,
    private val exporter: ResultExporter,
    private val settingsStore: SettingsStore
) : ViewModel() {
    private val filter = MutableStateFlow(ResultFilter.All)
    private val settings = MutableStateFlow(settingsStore.load())
    private val transient = MutableStateFlow(RootUiState())
    private var scanJob: Job? = null

    val state: StateFlow<RootUiState> = combine(filter, settings, repository.observeResults(), transient) { filterValue, settingsValue, results, current ->
        current.copy(
            filter = filterValue,
            settings = settingsValue,
            text = appText(settingsValue.language),
            results = applyFilter(results, filterValue),
            quickResults = results.filter { it.scanMode == ScanMode.Quick },
            bulkResults = results.filter { it.scanMode == ScanMode.Bulk }
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), RootUiState())

    fun setFilter(value: ResultFilter) {
        filter.value = value
    }

    fun quickScan(host: String, ports: String) {
        val endpoints = ports.split(',', ';', ' ')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }
            .distinct()
            .map { EndpointInput(host.trim(), it) }
        scan(endpoints, settings.value.scanOptions(), ScanMode.Quick)
    }

    fun bulkScan(text: String) {
        scan(EndpointParser.parse(text), settings.value.scanOptions(), ScanMode.Bulk)
    }

    fun bulkScan(text: String, ports: String) {
        val parsedPorts = ports.split(',', ';', ' ')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }
            .distinct()
        val expandedInput = if (parsedPorts.isEmpty()) {
            text
        } else {
            text.lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .flatMap { line ->
                    if (line.contains(':')) {
                        sequenceOf(line)
                    } else {
                        parsedPorts.asSequence().map { port -> "$line:$port" }
                    }
                }
                .joinToString("\n")
        }
        scan(EndpointParser.parse(expandedInput), settings.value.scanOptions(), ScanMode.Bulk)
    }

    fun cancelScan() {
        scanJob?.cancel()
        transient.value = transient.value.copy(activeScan = false, progressText = appText(settings.value.language).cancelled)
    }

    fun clear() {
        viewModelScope.launch { repository.clearHistory() }
    }

    fun export(format: String) {
        val results = state.value.results
        val text = when (format.lowercase()) {
            "csv" -> exporter.csv(results)
            "txt" -> exporter.txt(results)
            else -> exporter.json(results)
        }
        transient.value = transient.value.copy(exportText = text)
    }

    fun updateSettings(next: AppSettings) {
        val bounded = next.copy(retries = next.retries.coerceIn(1, 8), timeoutMillis = next.timeoutMillis.coerceIn(1000, 15000))
        settings.value = bounded
        settingsStore.save(bounded)
    }

    private fun scan(endpoints: List<EndpointInput>, options: ScanOptions, mode: ScanMode) {
        if (endpoints.isEmpty()) {
            transient.value = transient.value.copy(error = appText(settings.value.language).noValidEndpoints)
            return
        }
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            transient.value = transient.value.copy(activeScan = true, progressText = "0/${endpoints.size}", error = null)
            var done = 0
            runCatching {
                repository.scanBatch(endpoints, options, mode) {
                    done += 1
                    transient.value = transient.value.copy(progressText = "$done/${endpoints.size} ${it.endpoint}")
                }
            }.onFailure {
                transient.value = transient.value.copy(error = it.message ?: appText(settings.value.language).scanFailed)
            }
            transient.value = transient.value.copy(activeScan = false)
        }
    }

    private fun applyFilter(results: List<EndpointResult>, filter: ResultFilter) = results.filter {
        when (filter) {
            ResultFilter.All -> true
            ResultFilter.TunnelReady -> it.classification == "Tunnel Ready"
            ResultFilter.TlsCapable -> it.tls
            ResultFilter.WebSocketSupported -> it.webSocket
            ResultFilter.LowLatency -> it.rttMs in 1..149
            ResultFilter.HighStability -> it.stability >= 90
        }
    }
}
