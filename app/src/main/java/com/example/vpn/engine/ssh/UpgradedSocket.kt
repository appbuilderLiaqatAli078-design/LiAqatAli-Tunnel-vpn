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

    override fun setTcpNoDelay(on: Boolean) { underlyingSocket.tcpNoDelay = on }
    override fun getTcpNoDelay(): Boolean = underlyingSocket.tcpNoDelay

    override fun setSoTimeout(timeout: Int) { underlyingSocket.soTimeout = timeout }
    override fun getSoTimeout(): Int = underlyingSocket.soTimeout

    override fun setSendBufferSize(size: Int) { underlyingSocket.sendBufferSize = size }
    override fun getSendBufferSize(): Int = underlyingSocket.sendBufferSize
    override fun setReceiveBufferSize(size: Int) { underlyingSocket.receiveBufferSize = size }
    override fun getReceiveBufferSize(): Int = underlyingSocket.receiveBufferSize

    override fun setKeepAlive(on: Boolean) { underlyingSocket.keepAlive = on }
    override fun getKeepAlive(): Boolean = underlyingSocket.keepAlive

    override fun shutdownInput() { underlyingSocket.shutdownInput() }
    override fun shutdownOutput() { underlyingSocket.shutdownOutput() }

    override fun close() {
        try { upgradedInputStream.close() } catch (ignored: Exception) {}
        try { upgradedOutputStream.close() } catch (ignored: Exception) {}
        try { underlyingSocket.close() } catch (ignored: Exception) {}
    }
}
