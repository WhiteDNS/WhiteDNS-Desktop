package com.tunnelcheck.app

import com.tunnelcheck.app.data.export.EndpointParser
import org.junit.Assert.assertEquals
import org.junit.Test

class EndpointParserTest {
    @Test
    fun parsesColonAndCsvEndpoints() {
        val endpoints = EndpointParser.parse("example.com:443\n1.1.1.1,853")
        assertEquals(listOf("example.com:443", "1.1.1.1:853"), endpoints.map { it.key })
    }
}
