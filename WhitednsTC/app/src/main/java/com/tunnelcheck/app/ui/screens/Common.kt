package com.tunnelcheck.app.ui.screens

import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tunnelcheck.app.domain.model.EndpointResult
import com.tunnelcheck.app.domain.model.ResultFilter
import com.tunnelcheck.app.ui.AppText
import com.tunnelcheck.app.ui.RootUiState

@Composable
fun ScreenShell(title: String, state: RootUiState, scrollable: Boolean = false, content: @Composable () -> Unit) {
    val modifier = if (scrollable) {
        Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    } else {
        Modifier
            .fillMaxWidth()
            .padding(16.dp)
    }
    Column(modifier, verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text(title, style = MaterialTheme.typography.headlineMedium)
        if (state.activeScan) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(state.progressText, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
        }
        state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        content()
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun FilterChips(current: ResultFilter, onFilter: (ResultFilter) -> Unit) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        ResultFilter.entries.forEach { filter ->
            AssistChip(onClick = { onFilter(filter) }, label = { Text(filter.name) }, enabled = current != filter)
        }
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun FilterChips(current: ResultFilter, text: AppText, onFilter: (ResultFilter) -> Unit) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        ResultFilter.entries.forEach { filter ->
            AssistChip(onClick = { onFilter(filter) }, label = { Text(text.filters[filter] ?: filter.name) }, enabled = current != filter)
        }
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun ResultCard(result: EndpointResult, text: AppText) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column {
                    Text(result.endpoint, style = MaterialTheme.typography.titleMedium)
                    Text(text.classifications[result.classification] ?: result.classification, color = MaterialTheme.colorScheme.secondary)
                }
                Text(result.grade, style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.primary)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                proto("TCP", result.tcp, text)
                proto("TLS", result.tls, text)
                proto("WS", result.webSocket, text)
                proto("UDP", result.udp, text)
                proto("QUIC", result.quic, text)
                proto("DNS", result.dns, text)
            }
            Text("${text.rtt} ${result.rttMs} ms   ${text.jitter} ${result.jitterMs} ms   ${text.loss} ${result.packetLoss}%")
            Text("${text.stability} ${result.stability}%   ${text.confidence} ${result.confidence}%   ${text.score} ${result.score}")
            if (result.falsePositive) Text(text.falsePositiveWarning, color = MaterialTheme.colorScheme.tertiary)
        }
    }
}

@Composable
private fun proto(name: String, ok: Boolean, text: AppText) {
    AssistChip(onClick = {}, label = { Text("$name ${if (ok) text.ok else text.no}") })
}
