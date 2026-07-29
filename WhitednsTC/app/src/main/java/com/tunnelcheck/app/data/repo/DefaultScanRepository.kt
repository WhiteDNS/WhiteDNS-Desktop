package com.tunnelcheck.app.data.repo

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.tunnelcheck.app.data.local.ScanResultDao
import com.tunnelcheck.app.data.local.toEntity
import com.tunnelcheck.app.domain.model.EndpointInput
import com.tunnelcheck.app.domain.model.EndpointResult
import com.tunnelcheck.app.domain.model.ResultFilter
import com.tunnelcheck.app.domain.model.ScanMode
import com.tunnelcheck.app.domain.model.ScanOptions
import com.tunnelcheck.app.domain.repo.ScanRepository
import com.tunnelcheck.app.engine.TunnelEngine
import com.tunnelcheck.app.service.ScanForegroundService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DefaultScanRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dao: ScanResultDao,
    private val engine: TunnelEngine
) : ScanRepository {
    override fun observeResults(filter: ResultFilter): Flow<List<EndpointResult>> {
        return dao.observeAll().map { rows ->
            rows.map { it.toDomain() }.filter { result ->
                when (filter) {
                    ResultFilter.All -> true
                    ResultFilter.TunnelReady -> result.classification == "Tunnel Ready"
                    ResultFilter.TlsCapable -> result.tls
                    ResultFilter.WebSocketSupported -> result.webSocket
                    ResultFilter.LowLatency -> result.rttMs in 1..149
                    ResultFilter.HighStability -> result.stability >= 90
                }
            }
        }
    }

    override suspend fun scan(endpoint: EndpointInput, options: ScanOptions, mode: ScanMode): EndpointResult = withContext(Dispatchers.IO) {
        val result = engine.scan(endpoint, options).copy(tags = endpoint.tags, scanMode = mode)
        dao.insert(result.toEntity())
        result
    }

    override suspend fun scanBatch(endpoints: List<EndpointInput>, options: ScanOptions, mode: ScanMode, onProgress: suspend (EndpointResult) -> Unit) {
        withContext(Dispatchers.IO) {
            val useForegroundService = endpoints.size >= 10
            if (useForegroundService) {
                ContextCompat.startForegroundService(context, Intent(context, ScanForegroundService::class.java))
            }
            val limit = adaptiveLimit(endpoints.size)
            val semaphore = Semaphore(limit)
            try {
                endpoints.distinctBy { it.key }.map { endpoint ->
                    async {
                        semaphore.withPermit {
                            val result = scan(endpoint, options, mode)
                            onProgress(result)
                        }
                    }
                }.awaitAll()
            } finally {
                if (useForegroundService) {
                    context.stopService(Intent(context, ScanForegroundService::class.java))
                }
            }
        }
    }

    override suspend fun clearHistory() = dao.clear()

    private fun adaptiveLimit(size: Int) = when {
        size < 25 -> 6
        size < 250 -> 16
        else -> 32
    }
}
