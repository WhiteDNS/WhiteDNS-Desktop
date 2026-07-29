package com.tunnelcheck.app.domain.repo

import com.tunnelcheck.app.domain.model.EndpointInput
import com.tunnelcheck.app.domain.model.EndpointResult
import com.tunnelcheck.app.domain.model.ResultFilter
import com.tunnelcheck.app.domain.model.ScanMode
import com.tunnelcheck.app.domain.model.ScanOptions
import kotlinx.coroutines.flow.Flow

interface ScanRepository {
    fun observeResults(filter: ResultFilter = ResultFilter.All): Flow<List<EndpointResult>>
    suspend fun scan(endpoint: EndpointInput, options: ScanOptions, mode: ScanMode): EndpointResult
    suspend fun scanBatch(endpoints: List<EndpointInput>, options: ScanOptions, mode: ScanMode, onProgress: suspend (EndpointResult) -> Unit = {})
    suspend fun clearHistory()
}
