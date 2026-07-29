package com.tunnelcheck.app.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tunnelcheck.app.ui.RootUiState
import java.nio.charset.Charset

@Composable
fun BulkScanScreen(state: RootUiState, onScan: (String, String) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    var text by remember { mutableStateOf("104.16.132.229:443\ncloudflare.com:443") }
    var ports by remember { mutableStateOf("443,8443,2053") }
    var importError by remember { mutableStateOf<String?>(null) }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            runCatching { context.contentResolver.takePersistableUriPermission(uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            context.contentResolver.openInputStream(uri)?.use { stream ->
                stream.readBytes().toString(Charset.forName("UTF-8"))
            } ?: error(state.text.unableToOpenFile)
        }.onSuccess { imported ->
            text = imported
            importError = null
        }.onFailure { error ->
            importError = error.message ?: state.text.unableToImportFile
        }
    }
    ScreenShell(state.text.bulkScan, state) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = { filePicker.launch(arrayOf("text/plain", "text/csv", "application/json", "application/octet-stream")) },
                enabled = !state.activeScan
            ) {
                Text(state.text.importFile)
            }
        }
        importError?.let { Text(it) }
        OutlinedTextField(
            value = ports,
            onValueChange = { ports = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(state.text.ports) },
            singleLine = true
        )
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 220.dp, max = 320.dp),
            minLines = 8,
            maxLines = 12,
            label = { Text(state.text.pasteEndpoints) }
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(onClick = { onScan(text, ports) }, enabled = !state.activeScan) {
                Icon(Icons.Default.PlayArrow, contentDescription = null)
                Text(state.text.scan)
            }
            Button(onClick = onCancel, enabled = state.activeScan) {
                Text(state.text.cancel)
            }
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(state.bulkResults.take(20), key = { it.id }) { ResultCard(it, state.text) }
        }
    }
}
