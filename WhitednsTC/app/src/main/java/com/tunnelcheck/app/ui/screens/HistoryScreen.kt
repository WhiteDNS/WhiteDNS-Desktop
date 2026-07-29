package com.tunnelcheck.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp
import com.tunnelcheck.app.domain.model.ResultFilter
import com.tunnelcheck.app.ui.RootUiState

@Composable
fun HistoryScreen(state: RootUiState, onFilter: (ResultFilter) -> Unit, onClear: () -> Unit) {
    ScreenShell(state.text.history, state) {
        FilterChips(state.filter, state.text, onFilter)
        Button(onClick = onClear) { Text(state.text.clearHistory) }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(state.results, key = { it.id }) { ResultCard(it, state.text) }
        }
    }
}
