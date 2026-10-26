package com.example.data

import com.example.model.LogEntry
import com.example.model.LogLevel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.regex.Pattern

object AppLogger {
    private const val MAX_LOG_SIZE = 400
    private val logsQueue = ConcurrentLinkedDeque<LogEntry>()
    private val _logsFlow = MutableStateFlow<List<LogEntry>>(emptyList())
    val logsFlow: StateFlow<List<LogEntry>> = _logsFlow.asStateFlow()

    // Redaction patterns for secrets, credentials, tokens
    private val UUID_REGEX = Pattern.compile("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val PASSWORD_KEY_REGEX = Pattern.compile("(?i)(password|passwd|key|token|secret|uuid|auth)=([^\r\n&\\s]+)")
    private val SENSITIVE_PARAM_REGEX = Pattern.compile("(?i):([^:@/]+)@") // URI password user:pass@host

    fun log(level: LogLevel, tag: String, message: String) {
        val sanitized = redact(message)
        val entry = LogEntry(level = level, tag = tag, message = sanitized)
        logsQueue.add(entry)
        while (logsQueue.size > MAX_LOG_SIZE) {
            logsQueue.poll()
        }
        _logsFlow.value = logsQueue.toList()
        android.util.Log.println(
            when (level) {
                LogLevel.DEBUG -> android.util.Log.DEBUG
                LogLevel.INFO -> android.util.Log.INFO
                LogLevel.WARN -> android.util.Log.WARN
                LogLevel.ERROR -> android.util.Log.ERROR
            },
            tag,
            sanitized
        )
    }

    fun d(tag: String, message: String) = log(LogLevel.DEBUG, tag, message)
    fun i(tag: String, message: String) = log(LogLevel.INFO, tag, message)
    fun w(tag: String, message: String) = log(LogLevel.WARN, tag, message)
    fun e(tag: String, message: String, throwable: Throwable? = null) {
        val fullMsg = if (throwable != null) "$message: ${throwable.message}" else message
        log(LogLevel.ERROR, tag, fullMsg)
    }

    fun clear() {
        logsQueue.clear()
        _logsFlow.value = emptyList()
    }

    fun redact(input: String): String {
        var result = UUID_REGEX.matcher(input).replaceAll("********-****-****-****-************")
        result = PASSWORD_KEY_REGEX.matcher(result).replaceAll("$1=******")
        result = SENSITIVE_PARAM_REGEX.matcher(result).replaceAll(":******@")
        return result
    }
}
