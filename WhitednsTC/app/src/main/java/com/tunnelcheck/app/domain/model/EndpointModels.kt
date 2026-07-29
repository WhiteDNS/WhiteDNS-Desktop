package com.tunnelcheck.app.domain.model

data class EndpointInput(
    val host: String,
    val port: Int,
    val sni: String? = null,
    val tags: List<String> = emptyList()
) {
    val key: String = "$host:$port"
}

data class ScanOptions(
    val retries: Int = 3,
    val timeoutMillis: Int = 3500,
    val enableUdp: Boolean = true,
    val enableQuic: Boolean = true,
    val enableDns: Boolean = true,
    val enableWebSocket: Boolean = true,
    val allowInsecureCert: Boolean = false
)

enum class ScanMode {
    Quick,
    Bulk
}

data class EndpointResult(
    val id: Long = 0,
    val endpoint: String,
    val host: String,
    val port: Int,
    val tcp: Boolean,
    val tls: Boolean,
    val http: Boolean,
    val webSocket: Boolean,
    val udp: Boolean,
    val quic: Boolean,
    val dns: Boolean,
    val rttMs: Long,
    val jitterMs: Long,
    val packetLoss: Double,
    val stability: Double,
    val score: Int,
    val grade: String,
    val classification: String,
    val confidence: Double,
    val falsePositive: Boolean,
    val rawJson: String,
    val scanMode: ScanMode = ScanMode.Quick,
    val scannedAt: Long = System.currentTimeMillis(),
    val notes: String = "",
    val favorite: Boolean = false,
    val tags: List<String> = emptyList()
)

enum class ResultFilter {
    All,
    TunnelReady,
    TlsCapable,
    WebSocketSupported,
    LowLatency,
    HighStability
}
