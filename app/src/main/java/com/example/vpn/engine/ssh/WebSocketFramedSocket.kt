package com.example.vpn.engine.ssh

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

class WebSocketFramedSocket(
    underlyingSocket: Socket,
    rawInputStream: InputStream
) : UpgradedSocket(
    underlyingSocket = underlyingSocket.apply {
        try {
            tcpNoDelay = true
        } catch (_: Exception) {}
    },
    upgradedInputStream = PushbackInputStream(
        WebSocketFramedInputStream(
            rawInputStream,
            underlyingSocket.getOutputStream()
        ),
        8192
    ),
    upgradedOutputStream = WebSocketFramedOutputStream(
        underlyingSocket.getOutputStream()
    )
) {
    val pushbackInputStream: PushbackInputStream
        get() = upgradedInputStream as PushbackInputStream
}

class WebSocketFramedInputStream(
    private val rawIn: InputStream,
    private val rawOut: OutputStream
) : InputStream() {
    private val dataIn = DataInputStream(rawIn)
    private var buffer = ByteArray(16384)
    private var bufferOffset = 0
    private var bufferLimit = 0
    private val singleByteBuf = ByteArray(1)
    private val maskKey = ByteArray(4)
    private var closeFrameSent = false

    override fun read(): Int {
        val read = read(singleByteBuf, 0, 1)
        return if (read > 0) singleByteBuf[0].toInt() and 0xFF else -1
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0

        if (bufferOffset < bufferLimit) {
            val available = bufferLimit - bufferOffset
            val toCopy = minOf(len, available)
            System.arraycopy(buffer, bufferOffset, b, off, toCopy)
            bufferOffset += toCopy
            return toCopy
        }

        while (true) {
            val b0 = dataIn.read()
            if (b0 == -1) return -1
            val b1 = dataIn.read()
            if (b1 == -1) return -1

            val opcode = b0 and 0x0F
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

            if (isMasked) {
                dataIn.readFully(maskKey, 0, 4)
            }

            val intLen = payloadLen.toInt()
            if (opcode == 0x00 || opcode == 0x01 || opcode == 0x02) {
                if (intLen == 0) continue
                if (buffer.size < intLen) {
                    buffer = ByteArray(maxOf(intLen, 16384))
                }
                dataIn.readFully(buffer, 0, intLen)
                if (isMasked) {
                    for (i in 0 until intLen) {
                        buffer[i] = (buffer[i].toInt() xor maskKey[i and 3].toInt()).toByte()
                    }
                }
                val toCopy = minOf(len, intLen)
                System.arraycopy(buffer, 0, b, off, toCopy)
                bufferOffset = toCopy
                bufferLimit = intLen
                return toCopy
            } else {
                val controlPayload = ByteArray(intLen)
                if (intLen > 0) {
                    dataIn.readFully(controlPayload, 0, intLen)
                    if (isMasked) {
                        for (i in 0 until intLen) {
                            controlPayload[i] = (controlPayload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
                        }
                    }
                }
                when (opcode) {
                    0x09 -> sendControlFrame(0x8A, controlPayload)
                    0x0A -> {}
                    0x08 -> {
                        if (!closeFrameSent) {
                            closeFrameSent = true
                            try {
                                sendControlFrame(0x88, ByteArray(0))
                            } catch (_: Exception) {}
                        }
                        return -1
                    }
                    else -> throw IOException("Unsupported WebSocket opcode: 0x${opcode.toString(16)}")
                }
            }
        }
    }

    private fun sendControlFrame(opcodeWithFin: Int, payload: ByteArray) {
        val len = minOf(payload.size, 125)
        val maskInt = ThreadLocalRandom.current().nextInt()
        val m0 = (maskInt ushr 24) and 0xFF
        val m1 = (maskInt ushr 16) and 0xFF
        val m2 = (maskInt ushr 8) and 0xFF
        val m3 = maskInt and 0xFF
        val frame = ByteArray(6 + len)
        frame[0] = opcodeWithFin.toByte()
        frame[1] = (0x80 or len).toByte()
        frame[2] = m0.toByte()
        frame[3] = m1.toByte()
        frame[4] = m2.toByte()
        frame[5] = m3.toByte()
        for (i in 0 until len) {
            val maskByte = when (i and 3) {
                0 -> m0
                1 -> m1
                2 -> m2
                else -> m3
            }
            frame[6 + i] = (payload[i].toInt() xor maskByte).toByte()
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
    private val singleByte = ByteArray(1)
    private var scratchFrame = ByteArray(65536 + 14)

    override fun write(b: Int) {
        synchronized(rawOut) {
            singleByte[0] = b.toByte()
            writeLocked(singleByte, 0, 1)
        }
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        synchronized(rawOut) {
            writeLocked(b, off, len)
        }
    }

    private fun writeLocked(b: ByteArray, off: Int, len: Int) {
        val headerLen = when {
            len < 126 -> 2
            len <= 65535 -> 4
            else -> 10
        }
        val totalLen = headerLen + 4 + len
        if (scratchFrame.size < totalLen) {
            scratchFrame = ByteArray(totalLen)
        }
        val frame = scratchFrame
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

        val maskInt = ThreadLocalRandom.current().nextInt()
        val m0 = (maskInt ushr 24) and 0xFF
        val m1 = (maskInt ushr 16) and 0xFF
        val m2 = (maskInt ushr 8) and 0xFF
        val m3 = maskInt and 0xFF

        frame[headerLen] = m0.toByte()
        frame[headerLen + 1] = m1.toByte()
        frame[headerLen + 2] = m2.toByte()
        frame[headerLen + 3] = m3.toByte()

        val payloadStart = headerLen + 4
        for (i in 0 until len) {
            val maskByte = when (i and 3) {
                0 -> m0
                1 -> m1
                2 -> m2
                else -> m3
            }
            frame[payloadStart + i] = (b[off + i].toInt() xor maskByte).toByte()
        }

        rawOut.write(frame, 0, totalLen)
        rawOut.flush()
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
