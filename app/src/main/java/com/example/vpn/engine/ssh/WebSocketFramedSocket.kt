package com.example.vpn.engine.ssh

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import kotlin.random.Random

class WebSocketFramedSocket(
    underlyingSocket: Socket,
    rawInputStream: InputStream
) : UpgradedSocket(
    underlyingSocket = underlyingSocket,
    upgradedInputStream = WebSocketFramedInputStream(rawInputStream, underlyingSocket.getOutputStream()),
    upgradedOutputStream = WebSocketFramedOutputStream(underlyingSocket.getOutputStream())
)

class WebSocketFramedInputStream(
    private val rawIn: InputStream,
    private val rawOut: OutputStream
) : InputStream() {
    private val dataIn = DataInputStream(rawIn)
    private var buffer = ByteArray(0)
    private var bufferOffset = 0

    override fun read(): Int {
        val b = ByteArray(1)
        val read = read(b, 0, 1)
        return if (read > 0) b[0].toInt() and 0xFF else -1
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (!fillBuffer()) return -1

        val available = buffer.size - bufferOffset
        val toCopy = Math.min(len, available)
        System.arraycopy(buffer, bufferOffset, b, off, toCopy)
        bufferOffset += toCopy
        return toCopy
    }

    private fun fillBuffer(): Boolean {
        while (bufferOffset >= buffer.size) {
            val b0 = dataIn.read()
            if (b0 == -1) return false

            val opcode = b0 and 0x0F
            val b1 = dataIn.read()
            if (b1 == -1) return false

            val isMasked = (b1 and 0x80) != 0
            var payloadLen = (b1 and 0x7F).toLong()

            if (payloadLen == 126L) {
                payloadLen = (dataIn.readUnsignedShort()).toLong()
            } else if (payloadLen == 127L) {
                payloadLen = dataIn.readLong()
            }

            val mask = if (isMasked) {
                ByteArray(4).apply { dataIn.readFully(this) }
            } else null

            if (payloadLen > 10 * 1024 * 1024) {
                throw IllegalStateException("WebSocket frame exceeds 10MB limit: $payloadLen bytes")
            }

            val frameData = ByteArray(payloadLen.toInt())
            dataIn.readFully(frameData)

            if (mask != null) {
                for (i in frameData.indices) {
                    frameData[i] = (frameData[i].toInt() xor mask[i % 4].toInt()).toByte()
                }
            }

            when (opcode) {
                0x01, 0x02, 0x00 -> { // Text, Binary, or Continuation
                    buffer = frameData
                    bufferOffset = 0
                    return true
                }
                0x09 -> { // Ping -> Reply with Pong (0x8A)
                    synchronized(rawOut) {
                        rawOut.write(0x8A)
                        rawOut.write(0x80 or frameData.size)
                        val pongMask = ByteArray(4).apply { Random.nextBytes(this) }
                        rawOut.write(pongMask)
                        for (i in frameData.indices) {
                            rawOut.write(frameData[i].toInt() xor pongMask[i % 4].toInt())
                        }
                        rawOut.flush()
                    }
                }
                0x08 -> { // Close frame
                    return false
                }
            }
        }
        return true
    }

    override fun close() {
        rawIn.close()
    }
}

class WebSocketFramedOutputStream(
    private val rawOut: OutputStream
) : OutputStream() {

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len == 0) return
        val out = DataOutputStream(rawOut)
        synchronized(rawOut) {
            out.writeByte(0x82) // FIN=1, Opcode=2 (Binary Frame)

            val mask = ByteArray(4).apply { Random.nextBytes(this) }

            if (len < 126) {
                out.writeByte(0x80 or len)
            } else if (len <= 65535) {
                out.writeByte(0x80 or 126)
                out.writeShort(len)
            } else {
                out.writeByte(0x80 or 127)
                out.writeLong(len.toLong())
            }

            out.write(mask)

            val masked = ByteArray(len)
            for (i in 0 until len) {
                masked[i] = (b[off + i].toInt() xor mask[i % 4].toInt()).toByte()
            }
            out.write(masked)
            out.flush()
        }
    }

    override fun flush() {
        rawOut.flush()
    }

    override fun close() {
        rawOut.close()
    }
}
