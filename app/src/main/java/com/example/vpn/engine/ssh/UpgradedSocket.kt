package com.example.vpn.engine.ssh

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.net.SocketAddress

open class UpgradedSocket(
    protected val underlyingSocket: Socket,
    protected val upgradedInputStream: InputStream,
    protected val upgradedOutputStream: OutputStream = underlyingSocket.getOutputStream()
) : Socket() {

    override fun getInputStream(): InputStream = upgradedInputStream
    override fun getOutputStream(): OutputStream = upgradedOutputStream

    override fun isConnected(): Boolean = underlyingSocket.isConnected
    override fun isClosed(): Boolean = underlyingSocket.isClosed
    override fun isBound(): Boolean = underlyingSocket.isBound
    override fun isInputShutdown(): Boolean = underlyingSocket.isInputShutdown
    override fun isOutputShutdown(): Boolean = underlyingSocket.isOutputShutdown

    override fun getInetAddress(): InetAddress? = underlyingSocket.inetAddress
    override fun getPort(): Int = underlyingSocket.port
    override fun getLocalAddress(): InetAddress = underlyingSocket.localAddress
    override fun getLocalPort(): Int = underlyingSocket.localPort
    override fun getRemoteSocketAddress(): SocketAddress? = underlyingSocket.remoteSocketAddress
    override fun getLocalSocketAddress(): SocketAddress? = underlyingSocket.localSocketAddress

    override fun setTcpNoDelay(on: Boolean) {
        try { underlyingSocket.tcpNoDelay = on } catch (_: Exception) {}
    }
    override fun getTcpNoDelay(): Boolean = try { underlyingSocket.tcpNoDelay } catch (_: Exception) { true }

    override fun setSoTimeout(timeout: Int) {
        try { underlyingSocket.soTimeout = timeout } catch (_: Exception) {}
    }
    override fun getSoTimeout(): Int = try { underlyingSocket.soTimeout } catch (_: Exception) { 0 }

    override fun setSendBufferSize(size: Int) {
        try { underlyingSocket.sendBufferSize = size } catch (_: Exception) {}
    }
    override fun getSendBufferSize(): Int = try { underlyingSocket.sendBufferSize } catch (_: Exception) { 65536 }
    override fun setReceiveBufferSize(size: Int) {
        try { underlyingSocket.receiveBufferSize = size } catch (_: Exception) {}
    }
    override fun getReceiveBufferSize(): Int = try { underlyingSocket.receiveBufferSize } catch (_: Exception) { 65536 }

    override fun setKeepAlive(on: Boolean) {
        try { underlyingSocket.keepAlive = on } catch (_: Exception) {}
    }
    override fun getKeepAlive(): Boolean = try { underlyingSocket.keepAlive } catch (_: Exception) { false }

    override fun shutdownInput() {
        try { underlyingSocket.shutdownInput() } catch (_: Exception) {}
    }
    override fun shutdownOutput() {
        try { underlyingSocket.shutdownOutput() } catch (_: Exception) {}
    }

    override fun close() {
        try { upgradedInputStream.close() } catch (_: Exception) {}
        try { upgradedOutputStream.close() } catch (_: Exception) {}
        try { underlyingSocket.close() } catch (_: Exception) {}
    }
}
