// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.services

import ai.codetrust.plugin.settings.CodeTrustSettings
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * HTTP client for the CodeTrust cloud API.
 * Handles scan requests, authentication, and response parsing.
 */
object CodeTrustApiClient {
    private val gson = Gson()
    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    private fun buildClient(): OkHttpClient {
        val settings = CodeTrustSettings.getInstance().state
        return OkHttpClient.Builder()
            .connectTimeout(settings.connectionTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .readTimeout(settings.scanTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .writeTimeout(settings.scanTimeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .build()
    }

    /**
     * Send a static scan request to the CodeTrust API.
     * @param code The source code to scan.
     * @param filename The filename (used for language detection).
     * @return List of findings from the scan, or empty list on error.
     */
    fun scanCode(code: String, filename: String): List<Finding> {
        val settings = CodeTrustSettings.getInstance().state
        val endpoint = "${settings.apiEndpoint}/v1/scan/static"

        val payload = gson.toJson(
            mapOf(
                "code" to code,
                "filename" to filename,
                "include_info" to (settings.minimumSeverity == "INFO")
            )
        )

        val request = Request.Builder()
            .url(endpoint)
            .addHeader("X-API-Key", settings.apiKey)
            .addHeader("Content-Type", "application/json")
            .post(payload.toRequestBody(JSON_MEDIA))
            .build()

        return try {
            val client = buildClient()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return emptyList()
                }
                val body = response.body?.string() ?: return emptyList()
                parseScanResponse(body)
            }
        } catch (e: IOException) {
            emptyList()
        }
    }

    /**
     * Send a deep scan request (static + AST + registry verification).
     */
    fun deepScan(code: String, filename: String): List<Finding> {
        val settings = CodeTrustSettings.getInstance().state
        val endpoint = "${settings.apiEndpoint}/v1/scan/deep"

        val payload = gson.toJson(
            mapOf(
                "code" to code,
                "filename" to filename
            )
        )

        val request = Request.Builder()
            .url(endpoint)
            .addHeader("X-API-Key", settings.apiKey)
            .addHeader("Content-Type", "application/json")
            .post(payload.toRequestBody(JSON_MEDIA))
            .build()

        return try {
            val client = buildClient()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return emptyList()
                val body = response.body?.string() ?: return emptyList()
                parseScanResponse(body)
            }
        } catch (e: IOException) {
            emptyList()
        }
    }

    /**
     * Check API connectivity and authentication.
     * @return true if the API is reachable and the key is valid.
     */
    fun testConnection(): Boolean {
        val settings = CodeTrustSettings.getInstance().state
        val endpoint = "${settings.apiEndpoint}/health"

        val request = Request.Builder()
            .url(endpoint)
            .addHeader("X-API-Key", settings.apiKey)
            .get()
            .build()

        return try {
            val client = buildClient()
            client.newCall(request).execute().use { it.isSuccessful }
        } catch (e: IOException) {
            false
        }
    }

    private fun parseScanResponse(json: String): List<Finding> {
        return try {
            val response: Map<String, Any> = gson.fromJson(
                json,
                object : TypeToken<Map<String, Any>>() {}.type
            )

            @Suppress("UNCHECKED_CAST")
            val findings = response["findings"] as? List<Map<String, Any>> ?: return emptyList()

            findings.map { f ->
                Finding(
                    ruleId = f["rule_id"] as? String ?: f["id"] as? String ?: "unknown",
                    severity = parseSeverity(f["severity"] as? String ?: "WARN"),
                    message = f["message"] as? String ?: "",
                    suggestion = f["suggestion"] as? String,
                    line = (f["line"] as? Double)?.toInt(),
                    column = (f["column"] as? Double)?.toInt(),
                    file = f["file"] as? String
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun parseSeverity(value: String): Severity {
        return when (value.uppercase()) {
            "BLOCK" -> Severity.BLOCK
            "WARN" -> Severity.WARN
            "INFO" -> Severity.INFO
            else -> Severity.WARN
        }
    }
}

/** Severity levels matching the CodeTrust API. */
enum class Severity(val displayName: String, val weight: Int) {
    BLOCK("Block", 3),
    WARN("Warning", 2),
    INFO("Info", 1);
}

/** A single finding from a CodeTrust scan. */
data class Finding(
    val ruleId: String,
    val severity: Severity,
    val message: String,
    val suggestion: String? = null,
    val line: Int? = null,
    val column: Int? = null,
    val file: String? = null
)
