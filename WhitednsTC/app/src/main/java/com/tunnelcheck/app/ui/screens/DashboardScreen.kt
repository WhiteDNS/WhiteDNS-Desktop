package com.tunnelcheck.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tunnelcheck.app.domain.model.ResultFilter
import com.tunnelcheck.app.ui.RootUiState

@Composable
fun DashboardScreen(state: RootUiState, onFilter: (ResultFilter) -> Unit) {
    ScreenShell("WhiteDns TC", state) {
        Text("V1.0.0", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.secondary)
        val ready = state.results.count { it.classification == "Tunnel Ready" }
        val unstable = state.results.count { it.classification == "Unstable" || it.falsePositive }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            MetricBlock(state.text.tested, state.results.size.toString(), Modifier.weight(1f))
            MetricBlock(state.text.ready, ready.toString(), Modifier.weight(1f))
            MetricBlock(state.text.risky, unstable.toString(), Modifier.weight(1f))
        }
        FilterChips(state.filter, state.text, onFilter)
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(state.results, key = { it.id }) { result ->
                ResultCard(result, state.text)
            }
        }
    }
}

@Composable
private fun MetricBlock(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier) {
        Text(value, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
        Text(label, style = MaterialTheme.typography.labelLarge)
    }
}
