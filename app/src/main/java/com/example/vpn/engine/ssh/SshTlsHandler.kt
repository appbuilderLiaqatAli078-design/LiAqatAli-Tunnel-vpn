package com.example.vpn.engine.ssh

import com.example.data.AppLogger
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

object SshTlsHandler {
    private const val TAG = "SshTlsHandler"

    private val permissiveTrustManager = arrayOf<TrustManager>(
        object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
    )

    fun wrapTls(
        underlyingSocket: Socket,
        sniHost: String,
        targetPort: Int,
        allowInsecure: Boolean = false,
        handshakeTimeoutMs: Int = 10000
    ): SSLSocket {
        AppLogger.i(TAG, "Wrapping socket in SSL/TLS with SNI='$sniHost', allowInsecure=$allowInsecure")

        val sslContext = SSLContext.getInstance("TLS")
        if (allowInsecure) {
            sslContext.init(null, permissiveTrustManager, SecureRandom())
        } else {
            sslContext.init(null, null, SecureRandom())
        }

        val sslSocketFactory = sslContext.socketFactory
        val sslSocket = sslSocketFactory.createSocket(
            underlyingSocket,
            sniHost,
            targetPort,
            true // autoClose underlying socket
        ) as SSLSocket

        try {
            val sslParams = sslSocket.sslParameters
            if (sniHost.isNotBlank()) {
                sslParams.serverNames = listOf(SNIHostName(sniHost))
            }
            sslSocket.sslParameters = sslParams
            sslSocket.enabledProtocols = sslSocket.supportedProtocols.filter {
                it == "TLSv1.2" || it == "TLSv1.3"
            }.toTypedArray()
        } catch (e: Exception) {
            AppLogger.w(TAG, "Could not set SNI host or protocols: ${e.message}")
        }

        val prevTimeout = underlyingSocket.soTimeout
        sslSocket.soTimeout = handshakeTimeoutMs
        sslSocket.startHandshake()
        sslSocket.soTimeout = prevTimeout

        AppLogger.i(TAG, "TLS handshake completed successfully (${sslSocket.session.protocol}, ${sslSocket.session.cipherSuite})")
        return sslSocket
    }
}
