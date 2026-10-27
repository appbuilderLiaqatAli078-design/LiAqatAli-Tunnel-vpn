package com.example.vpn.engine.ssh

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.Socket
import kotlin.random.Random

class WebSocketFramedSocket(
    underlyingSocket: Socket,
    rawInputStream: InputStream
) : UpgradedSocket(
    underlyingSocket = underlyingSocket,
    upgradedInputStream = PushbackInputStream(
        WebSocketFramedInputStream(rawInputStream, underlyingSocket.getOutputStream()),
        8192
    ),
    upgradedOutputStream = WebSocketFramedOutputStream(underlyingSocket.getOutputStream())
) {
    val pushbackInputStream: PushbackInputStream
        get() = upgradedInputStream as PushbackInputStream
}

class WebSocketFramedInputStream(
    private val rawIn: InputStream,
    private val rawOut: OutputStream
) : InputStream() {
    private val dataIn = DataInputStream(rawIn)
    private var buffer = ByteArray(0)
    private var bufferOffset = 0
    private var closeFrameSent = false

    override fun read(): Int {
        val b = ByteArray(1)
        val read = read(b, 0, 1)
        return if (read > 0) b[0].toInt() and 0xFF else -1
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (!fillBuffer()) return -1

        val available = buffer.size - bufferOffset
        val toCopy = minOf(len, available)
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
                payloadLen = dataIn.readUnsignedShort().toLong()
            } else if (payloadLen == 127L) {
                payloadLen = dataIn.readLong()
            }

            if (payloadLen < 0L || payloadLen > 10L * 1024L * 1024L) {
                throw IOException("WebSocket frame length out of bounds: $payloadLen bytes")
            }

            val mask = if (isMasked) {
                ByteArray(4).apply { dataIn.readFully(this) }
            } else null

            val frameData = ByteArray(payloadLen.toInt())
            if (frameData.isNotEmpty()) {
                dataIn.readFully(frameData)
            }

            if (mask != null) {
                for (i in frameData.indices) {
                    frameData[i] = (frameData[i].toInt() xor mask[i and 3].toInt()).toByte()
                }
            }

            when (opcode) {
                0x00, 0x01, 0x02 -> { // Continuation, Text, or Binary
                    if (frameData.isNotEmpty()) {
                        buffer = frameData
                        bufferOffset = 0
                        return true
                    }
                    // Empty data frame: continue reading next frame
                }
                0x09 -> { // Ping -> Reply with masked Pong (0x8A)
                    sendControlFrame(0x8A, frameData)
                }
                0x0A -> { // Pong -> Ignore and continue
                }
                0x08 -> { // Close frame -> Reply with masked Close frame and signal EOF
                    if (!closeFrameSent) {
                        closeFrameSent = true
                        try {
                            sendControlFrame(0x88, ByteArray(0))
                        } catch (_: Exception) {}
                    }
                    return false
                }
                else -> {
                    throw IOException("Unsupported WebSocket opcode: 0x${opcode.toString(16)}")
                }
            }
        }
        return true
    }

    private fun sendControlFrame(opcodeWithFin: Int, payload: ByteArray) {
        val len = minOf(payload.size, 125)
        val mask = ByteArray(4).apply { Random.nextBytes(this) }
        val frame = ByteArray(2 + 4 + len)
        frame[0] = opcodeWithFin.toByte()
        frame[1] = (0x80 or len).toByte()
        System.arraycopy(mask, 0, frame, 2, 4)
        for (i in 0 until len) {
            frame[6 + i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()
        }
        synchronized(rawOut) {
            rawOut.write(frame)
            rawOut.flush()
        }
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
        if (len <= 0) return

        val headerLen = when {
            len < 126 -> 2
            len <= 65535 -> 4
            else -> 10
        }
        val frame = ByteArray(headerLen + 4 + len)
        frame[0] = 0x82.toByte() // FIN=1, Opcode=2 (Binary Frame)

        when {
            len < 126 -> {
                frame[1] = (0x80 or len).toByte()
            }
            len <= 65535 -> {
                frame[1] = (0x80 or 126).toByte()
                frame[2] = ((len ushr 8) and 0xFF).toByte()
                frame[3] = (len and 0xFF).toByte()
            }
            else -> {
                frame[1] = (0x80 or 127).toByte()
                val l = len.toLong()
                for (i in 0..7) {
                    frame[2 + i] = ((l ushr ((7 - i) * 8)) and 0xFF).toByte()
                }
            }
        }

        val mask = ByteArray(4).apply { Random.nextBytes(this) }
        System.arraycopy(mask, 0, frame, headerLen, 4)

        val payloadStart = headerLen + 4
        for (i in 0 until len) {
            frame[payloadStart + i] = (b[off + i].toInt() xor mask[i and 3].toInt()).toByte()
        }

        synchronized(rawOut) {
            rawOut.write(frame)
            rawOut.flush()
        }
    }

    override fun flush() {
        synchronized(rawOut) {
            rawOut.flush()
        }
    }

    override fun close() {
        rawOut.close()
    }
}
