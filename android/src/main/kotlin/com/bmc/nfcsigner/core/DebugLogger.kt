package com.bmc.nfcsigner.core

import android.content.Context
import android.content.pm.ApplicationInfo
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Logger nội bộ của plugin.
 *
 * Chỉ hoạt động khi ứng dụng chủ là bản debuggable (`android:debuggable`), và
 * khi đó cũng chỉ ghi vào bộ nhớ riêng của ứng dụng (`filesDir`), không ghi ra
 * bộ nhớ ngoài. Bản release không log gì cả.
 *
 * Không bao giờ truyền APDU thô vào đây — dùng [redactCommand] /
 * [describeResponse]: lệnh VERIFY chứa PIN dạng rõ, còn phản hồi của
 * PSO:DECIPHER là bản rõ đã giải mã.
 */
class DebugLogger(private val tag: String) {

    companion object {
        @Volatile
        private var enabled = false
        private var logFile: File? = null
        private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

        /**
         * Gọi 1 lần khi plugin gắn vào engine.
         *
         * Log file (chỉ bản debug): {filesDir}/ccid_debug.log
         * Lấy file: adb shell run-as <package> cat files/ccid_debug.log
         */
        fun init(context: Context) {
            enabled = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            if (!enabled) {
                logFile = null
                return
            }
            logFile = File(context.filesDir, "ccid_debug.log")
            try {
                FileWriter(logFile, true).use { writer ->
                    writer.appendLine("\n===== Session ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())} =====")
                }
            } catch (_: Exception) {}
        }

        /** Trả về nội dung log file (để hiển thị trong UI hoặc share) */
        fun getLogContent(): String {
            return logFile?.takeIf { it.exists() }?.readText() ?: "(no log)"
        }

        /** Xóa log file */
        fun clearLog() {
            logFile?.takeIf { it.exists() }?.delete()
        }

        /** Trả về đường dẫn log file */
        fun getLogFile(): File? = logFile

        private const val INS_VERIFY = 0x20
        private const val INS_CHANGE_REFERENCE_DATA = 0x24
        private const val INS_RESET_RETRY_COUNTER = 0x2C

        /**
         * Mô tả một lệnh APDU để ghi log mà không làm lộ dữ liệu nhạy cảm.
         *
         * Chỉ ghi header (CLA INS P1 P2) và độ dài dữ liệu. Phần dữ liệu chỉ được
         * hiện khi lệnh không mang bí mật (không phải VERIFY / CHANGE REFERENCE
         * DATA / RESET RETRY COUNTER).
         */
        fun redactCommand(command: ByteArray): String {
            if (command.size < 4) return "(${command.size} bytes)"
            val header = command.copyOfRange(0, 4).toHex()
            val ins = command[1].toInt() and 0xFF
            val dataLen = if (command.size > 5) command.size - 5 else 0
            return when (ins) {
                INS_VERIFY, INS_CHANGE_REFERENCE_DATA, INS_RESET_RETRY_COUNTER ->
                    "$header [secret: $dataLen bytes]"
                else -> "$header [data: $dataLen bytes]"
            }
        }

        /** Mô tả phản hồi: chỉ độ dài và SW, không bao giờ in dữ liệu. */
        fun describeResponse(data: ByteArray, sw1: Int, sw2: Int): String =
            "${data.size} bytes, SW=%02X%02X".format(sw1, sw2)

        private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
    }

    fun debug(message: String) {
        if (!enabled) return
        val timestamp = dateFormat.format(Date())
        val line = "$timestamp [$tag] $message"
        println(line)

        logFile?.let { file ->
            try {
                FileWriter(file, true).use { writer ->
                    writer.appendLine(line)
                }
            } catch (_: Exception) {}
        }
    }
}
