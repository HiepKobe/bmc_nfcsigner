package com.bmc.nfcsigner

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat
import com.bmc.nfcsigner.core.CardOperationManager
import com.bmc.nfcsigner.core.CardStatusException
import com.bmc.nfcsigner.core.DebugLogger
import com.bmc.nfcsigner.models.SignatureConfig
import com.bmc.nfcsigner.nfc.NfcCardManager
import com.bmc.nfcsigner.pdf.PdfSigningHelper
import com.bmc.nfcsigner.pdf.PinVerificationException
import com.bmc.nfcsigner.usb.UsbCardManager
import com.bmc.nfcsigner.usb.UsbDeviceManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class NfcsignerPlugin : FlutterPlugin, MethodCallHandler, ActivityAware, NfcAdapter.ReaderCallback {

  companion object {
    /** Các lệnh cần chạm/cắm thẻ. Lệnh khác KHÔNG được bật đầu đọc NFC. */
    private val CARD_METHODS = setOf(
      "generateSignature",
      "internalAuthenticate",
      "getRsaPublicKey",
      "getCertificate",
      "signPdf",
      "generateXMLSignature",
      "decryptData",
      "getPinRetryCounter",
    )
  }

  private lateinit var channel: MethodChannel
  private lateinit var promptChannel: EventChannel
  private lateinit var readerStateChannel: EventChannel
  private var nfcAdapter: NfcAdapter? = null
  private var currentActivity: Activity? = null

  /** Lệnh NFC đang chờ chạm thẻ. Chỉ truy cập trên main thread. */
  private var pending: PendingRequest? = null

  /** Có thao tác thẻ (NFC hoặc USB) đang chạy — thẻ chỉ phục vụ một lệnh một lúc. */
  private val busy = AtomicBoolean(false)

  private lateinit var nfcCardManager: NfcCardManager
  private lateinit var usbDeviceManager: UsbDeviceManager
  private lateinit var usbCardManager: UsbCardManager

  private val logger = DebugLogger("NfcsignerPlugin")
  private lateinit var applicationContext: Context
  private val mainHandler = Handler(Looper.getMainLooper())
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

  private var promptSink: EventChannel.EventSink? = null
  private var readerStateSink: EventChannel.EventSink? = null
  private var usbAttachReceiver: BroadcastReceiver? = null

  // ---------------------------------------------------------------------------
  // Kết quả trả về Dart: luôn trên main thread, và đúng một lần.
  // ---------------------------------------------------------------------------

  private inner class OnceResult(private val result: Result) {
    private val replied = AtomicBoolean(false)

    fun success(value: Any?) {
      if (replied.compareAndSet(false, true)) mainHandler.post { result.success(value) }
    }

    fun error(code: String, message: String?, details: Any? = null) {
      if (replied.compareAndSet(false, true)) mainHandler.post { result.error(code, message, details) }
    }

    fun notImplemented() {
      if (replied.compareAndSet(false, true)) mainHandler.post { result.notImplemented() }
    }
  }

  private class PendingRequest(val call: MethodCall, val result: OnceResult)

  // ---------------------------------------------------------------------------
  // Vòng đời
  // ---------------------------------------------------------------------------

  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    applicationContext = flutterPluginBinding.applicationContext
    DebugLogger.init(applicationContext)

    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "nfcsigner")
    channel.setMethodCallHandler(this)

    promptChannel = EventChannel(flutterPluginBinding.binaryMessenger, "nfcsigner/card_prompt")
    promptChannel.setStreamHandler(object : EventChannel.StreamHandler {
      override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        promptSink = events
      }

      override fun onCancel(arguments: Any?) {
        promptSink = null
      }
    })

    readerStateChannel = EventChannel(flutterPluginBinding.binaryMessenger, "nfcsigner/reader_state")
    readerStateChannel.setStreamHandler(object : EventChannel.StreamHandler {
      override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        readerStateSink = events
        registerUsbAttachReceiver()
        emitReaderState()
      }

      override fun onCancel(arguments: Any?) {
        readerStateSink = null
        unregisterUsbAttachReceiver()
      }
    })

    nfcAdapter = NfcAdapter.getDefaultAdapter(applicationContext)
    nfcCardManager = NfcCardManager()

    try {
      usbDeviceManager = UsbDeviceManager(applicationContext)
      usbCardManager = UsbCardManager(usbDeviceManager)
    } catch (e: Exception) {
      logger.debug("Failed to initialize USB managers: ${e.message}")
    }
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
    promptChannel.setStreamHandler(null)
    readerStateChannel.setStreamHandler(null)
    unregisterUsbAttachReceiver()
    scope.cancel()
  }

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    currentActivity = binding.activity
    // Activity context cần cho hộp thoại xin quyền USB.
    if (this::usbDeviceManager.isInitialized) usbDeviceManager.cleanup()
    usbDeviceManager = UsbDeviceManager(binding.activity)
    usbCardManager = UsbCardManager(usbDeviceManager)
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    onAttachedToActivity(binding)
  }

  override fun onDetachedFromActivityForConfigChanges() {
    onDetachedFromActivity()
  }

  override fun onDetachedFromActivity() {
    // Không còn Activity thì reader mode cũng tắt: huỷ lệnh đang chờ, đừng để
    // Future phía Dart treo.
    cancelPending("CANCELLED", "Ứng dụng đã rời màn hình trong lúc chờ thẻ.")
    if (this::usbDeviceManager.isInitialized) usbDeviceManager.cleanup()
    currentActivity = null
  }

  // ---------------------------------------------------------------------------
  // Điều phối
  // ---------------------------------------------------------------------------

  override fun onMethodCall(call: MethodCall, result: Result) {
    when (call.method) {
      "isCardReaderAttached" -> {
        result.success(isUsbReaderConnected())
        return
      }
      "cancelNfcWait", "cancelNfc" -> {
        cancelPending("CANCELLED", "Thao tác đã bị hủy.")
        result.success(true)
        return
      }
    }

    if (call.method !in CARD_METHODS) {
      // Kể cả openSession/decryptBatch/...: trả ngay để Dart dùng đường lui,
      // không bật đầu đọc NFC bắt người dùng chạm thẻ vô ích.
      result.notImplemented()
      return
    }

    if (!busy.compareAndSet(false, true)) {
      result.error("BUSY", "Đang có một thao tác thẻ khác chưa hoàn tất.", null)
      return
    }

    val once = OnceResult(result)
    if (isUsbReaderConnected()) {
      handleUsbRequest(call, once)
    } else {
      handleNfcRequest(call, once)
    }
  }

  private fun finish() {
    busy.set(false)
  }

  // ---------------------------------------------------------------------------
  // NFC
  // ---------------------------------------------------------------------------

  private fun handleNfcRequest(call: MethodCall, result: OnceResult) {
    val adapter = nfcAdapter
    if (adapter == null || !adapter.isEnabled) {
      result.error("NFC_UNAVAILABLE",
        if (adapter == null) "Thiết bị không hỗ trợ NFC." else "NFC đang tắt.", null)
      finish()
      return
    }
    val activity = currentActivity
    if (activity == null) {
      result.error("NO_ACTIVITY", "Plugin không thể truy cập Activity.", null)
      finish()
      return
    }

    pending = PendingRequest(call, result)
    adapter.enableReaderMode(
      activity, this,
      NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
      null
    )
    emitPrompt("waiting", call)
  }

  override fun onTagDiscovered(tag: Tag?) {
    // Gọi trên binder thread — lấy lệnh đang chờ trên main thread cho an toàn.
    mainHandler.post {
      val request = pending ?: return@post
      if (tag == null) return@post
      pending = null
      emitPrompt("reading", request.call)

      scope.launch {
        try {
          val ok = nfcCardManager.executeWithNfcCard(tag) { cardManager ->
            executeCommand(cardManager, request.call, request.result)
          }
          if (!ok) {
            request.result.error("TAG_NOT_SUPPORTED", "Thẻ không hỗ trợ ISO 14443-4 (IsoDep).", null)
          }
        } catch (e: Exception) {
          request.result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp với thẻ: ${e.message}", null)
        } finally {
          mainHandler.post {
            disableReaderMode()
            emitPrompt("done", request.call)
            finish()
          }
        }
      }
    }
  }

  /** Huỷ lệnh NFC đang chờ chạm thẻ (nếu có). Gọi trên main thread. */
  private fun cancelPending(code: String, message: String) {
    val request = pending ?: return
    pending = null
    disableReaderMode()
    request.result.error(code, message, null)
    emitPrompt("done", request.call)
    finish()
  }

  private fun disableReaderMode() {
    currentActivity?.let {
      try {
        nfcAdapter?.disableReaderMode(it)
      } catch (e: Exception) {
        logger.debug("disableReaderMode failed: ${e.message}")
      }
    }
  }

  // ---------------------------------------------------------------------------
  // USB
  // ---------------------------------------------------------------------------

  private fun isUsbReaderConnected(): Boolean {
    if (!this::usbDeviceManager.isInitialized) return false
    return try {
      usbDeviceManager.isSmartCardReaderConnected()
    } catch (e: Exception) {
      false
    }
  }

  private fun handleUsbRequest(call: MethodCall, result: OnceResult) {
    if (!usbDeviceManager.hasPermission()) {
      if (currentActivity == null) {
        result.error("NO_ACTIVITY", "Không thể xin quyền USB khi không có Activity.", null)
        finish()
        return
      }
      usbDeviceManager.requestPermission { granted ->
        if (granted) {
          handleUsbRequest(call, result)
        } else {
          result.error("USB_PERMISSION_DENIED", "Người dùng từ chối quyền truy cập đầu đọc USB.", null)
          finish()
        }
      }
      return
    }

    scope.launch {
      try {
        val success = usbCardManager.executeWithUsbCard { cardManager ->
          executeCommand(cardManager, call, result)
        }
        if (!success) {
          result.error("COMMUNICATION_ERROR", "Không kết nối được đầu đọc USB.", null)
        }
      } catch (e: Exception) {
        result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp USB: ${e.message}", null)
      } finally {
        finish()
      }
    }
  }

  private fun registerUsbAttachReceiver() {
    if (usbAttachReceiver != null) return
    val receiver = object : BroadcastReceiver() {
      override fun onReceive(context: Context, intent: Intent) {
        // Danh sách thiết bị có thể chưa cập nhật ngay lúc nhận broadcast.
        mainHandler.postDelayed({ emitReaderState() }, 300)
      }
    }
    val filter = IntentFilter(UsbManager.ACTION_USB_DEVICE_ATTACHED).apply {
      addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
    }
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        ContextCompat.registerReceiver(applicationContext, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
      } else {
        applicationContext.registerReceiver(receiver, filter)
      }
      usbAttachReceiver = receiver
    } catch (e: Exception) {
      logger.debug("Failed to register USB attach receiver: ${e.message}")
    }
  }

  private fun unregisterUsbAttachReceiver() {
    val receiver = usbAttachReceiver ?: return
    usbAttachReceiver = null
    try {
      applicationContext.unregisterReceiver(receiver)
    } catch (_: Exception) {}
  }

  private fun emitReaderState() {
    val sink = readerStateSink ?: return
    val attached = isUsbReaderConnected()
    mainHandler.post { sink.success(mapOf("attached" to attached)) }
  }

  // ---------------------------------------------------------------------------
  // Lời nhắc chạm thẻ (Android không tự hiện gì khi bật reader mode)
  // ---------------------------------------------------------------------------

  private fun emitPrompt(state: String, call: MethodCall) {
    val sink = promptSink ?: return
    val event = mapOf("state" to state, "task" to taskOf(call))
    mainHandler.post { sink.success(event) }
  }

  private fun taskOf(call: MethodCall): String = when (call.method) {
    "generateSignature", "internalAuthenticate" -> "sign"
    "getRsaPublicKey" -> when (call.argument<String>("keyRole")) {
      "sig" -> "readSigningKey"
      "dec" -> "readDecryptionKey"
      else -> "readKey"
    }
    "getCertificate" -> "readCertificate"
    "signPdf" -> "signPdf"
    "generateXMLSignature" -> "signXml"
    "decryptData" -> if (call.argument<String>("purpose") == "kdsChallenge") "verifyCard" else "decrypt"
    else -> "unknown"
  }

  // ---------------------------------------------------------------------------
  // Thao tác thẻ (chạy trên IO thread)
  // ---------------------------------------------------------------------------

  private fun executeCommand(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    try {
      when (call.method) {
        "generateSignature" -> handleGenerateSignature(cardManager, call, result)
        "internalAuthenticate" -> handleInternalAuthenticate(cardManager, call, result)
        "getRsaPublicKey" -> handleGetRsaPublicKey(cardManager, call, result)
        "getCertificate" -> handleGetCertificate(cardManager, call, result)
        "signPdf" -> handleSignPdf(cardManager, call, result)
        "generateXMLSignature" -> handleGenerateXMLSignature(cardManager, call, result)
        "decryptData" -> handleDecryptData(cardManager, call, result)
        "getPinRetryCounter" -> handleGetPinRetryCounter(cardManager, call, result)
        else -> result.notImplemented()
      }
    } catch (e: MissingArgumentException) {
      result.error("INVALID_PARAMETERS", e.message, null)
    } catch (e: IllegalArgumentException) {
      result.error("INVALID_PARAMETERS", e.message, null)
    } catch (e: CardStatusException) {
      result.error("COMMUNICATION_ERROR", e.message, mapOf("sw1" to e.sw1, "sw2" to e.sw2))
    } catch (e: Exception) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp I/O: ${e.message}", null)
    }
  }

  private class MissingArgumentException(name: String) : Exception("Thiếu tham số: $name")

  private inline fun <reified T> MethodCall.require(name: String): T =
    argument<T>(name) ?: throw MissingArgumentException(name)

  /** SELECT applet; trả false (và đã báo lỗi) nếu thất bại. */
  private fun select(cardManager: CardOperationManager, call: MethodCall, result: OnceResult): Boolean {
    val appletID = call.require<String>("appletID")
    if (!cardManager.selectApplet(hexStringToByteArray(appletID))) {
      result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", null)
      return false
    }
    return true
  }

  private fun reportPinFailure(result: OnceResult, triesLeft: Int) {
    val message = if (triesLeft > 0) "Xác thực PIN thất bại. Còn $triesLeft lần thử."
    else "Xác thực PIN thất bại."
    result.error("AUTH_ERROR", message, mapOf("triesLeft" to triesLeft))
  }

  private fun handleGenerateSignature(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    val pin = call.require<String>("pin")
    val dataToSign = call.require<ByteArray>("dataToSign")
    val keyIndex = call.argument<Int>("keyIndex") ?: 0
    if (!select(cardManager, call, result)) return

    val (pinVerified, triesLeft) = cardManager.verifyPin(pin)
    if (!pinVerified) return reportPinFailure(result, triesLeft)

    result.success(cardManager.generateSignature(dataToSign, keyIndex))
  }

  private fun handleInternalAuthenticate(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    val pin = call.require<String>("pin")
    val dataToSign = call.require<ByteArray>("dataToSign")
    if (!select(cardManager, call, result)) return

    // Khóa AUT dùng PW1 mode 0x82, giống giải mã.
    val (pinVerified, triesLeft) = cardManager.verifyPinForDecrypt(pin)
    if (!pinVerified) return reportPinFailure(result, triesLeft)

    result.success(cardManager.internalAuthenticate(dataToSign))
  }

  private fun handleGetRsaPublicKey(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    val keyRole = call.require<String>("keyRole")
    if (!select(cardManager, call, result)) return
    result.success(cardManager.getRsaPublicKey(keyRole))
  }

  private fun handleGetCertificate(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    val keyRole = call.require<String>("keyRole")
    if (!select(cardManager, call, result)) return
    result.success(cardManager.getCertificate(keyRole))
  }

  private fun handleGetPinRetryCounter(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    if (!select(cardManager, call, result)) return
    result.success(cardManager.getPinRetryCounter())
  }

  private fun handleSignPdf(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    val pdfBytes = call.require<ByteArray>("pdfBytes")
    val appletID = call.require<String>("appletID")
    val pin = call.require<String>("pin")
    val keyIndex = call.argument<Int>("keyIndex") ?: 0
    val reason = call.argument<String>("reason") ?: ""
    val location = call.argument<String>("location") ?: ""
    val signatureConfig = SignatureConfig.fromMap(call.argument<Map<String, Any>>("signatureConfig"))

    try {
      val signedPdf = PdfSigningHelper(applicationContext).signPdf(
        pdfBytes, cardManager, appletID, pin, keyIndex, reason, location, signatureConfig
      )
      result.success(signedPdf)
    } catch (e: PinVerificationException) {
      reportPinFailure(result, e.triesLeft)
    } catch (e: CardStatusException) {
      throw e
    } catch (e: Exception) {
      logger.debug("PDF signing error: ${e.message}")
      result.error("PDF_SIGN_ERROR", "Lỗi khi ký PDF: ${e.message}", null)
    }
  }

  private fun handleGenerateXMLSignature(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    val pin = call.require<String>("pin")
    val dataToSign = call.require<ByteArray>("dataToSign")
    val keyIndex = call.argument<Int>("keyIndex") ?: 0
    if (!select(cardManager, call, result)) return

    val (pinVerified, triesLeft) = cardManager.verifyPin(pin)
    if (!pinVerified) return reportPinFailure(result, triesLeft)

    val signature = cardManager.generateSignature(dataToSign, keyIndex)
    val certificate = cardManager.getCertificate("sig")

    result.success(mapOf(
      "certificate" to android.util.Base64.encodeToString(certificate, android.util.Base64.NO_WRAP),
      "signature" to android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP),
    ))
  }

  private fun handleDecryptData(cardManager: CardOperationManager, call: MethodCall, result: OnceResult) {
    val pin = call.require<String>("pin")
    val encryptedData = call.require<ByteArray>("encryptedData")
    if (!select(cardManager, call, result)) return

    val (pinVerified, triesLeft) = cardManager.verifyPinForDecrypt(pin)
    if (!pinVerified) return reportPinFailure(result, triesLeft)

    result.success(cardManager.decryptData(encryptedData))
  }

  private fun hexStringToByteArray(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "AID phải có số ký tự hex chẵn" }
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  }
}
