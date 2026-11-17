package com.bmc.nfcsigner.nfc

import android.nfc.tech.IsoDep
import com.bmc.nfcsigner.core.Transceiver
import com.bmc.nfcsigner.core.ResponseHandler
import com.bmc.nfcsigner.core.DebugLogger
import com.bmc.nfcsigner.models.ApduResponse
import java.io.IOException

class NfcTransceiver(private val isoDep: IsoDep) : Transceiver {

    private val logger = DebugLogger("NfcTransceiver")

    override fun connect() {
        if (!isoDep.isConnected) {
            isoDep.connect()
            isoDep.timeout = 5000
        }
    }

    override fun disconnect() {
        try {
            if (isoDep.isConnected) {
                isoDep.close()
            }
        } catch (e: IOException) {
            logger.debug("Error disconnecting NFC: ${e.message}")
        }
    }

    override fun isConnected(): Boolean = isoDep.isConnected

    @Throws(IOException::class)
    override fun transceive(command: ByteArray): ApduResponse {
        logger.debug("NFC → ${DebugLogger.redactCommand(command)}")

        connect()

        val response = isoDep.transceive(command)
        val apduResponse = ResponseHandler.parseResponse(response)

        logger.debug("NFC ← ${DebugLogger.describeResponse(apduResponse.data, apduResponse.sw1, apduResponse.sw2)}")

        return apduResponse
    }
}