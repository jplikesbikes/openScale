/*
 * openScale
 * Copyright (C) 2025 olie.xdev <olie.xdeveloper@googlemail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Minimal XXTEA (Corrected Block TEA) implementation for 8-byte blocks.
 *
 * The Wyze Scale X encrypts individual 8-byte blocks independently using a 16-byte key.
 * This matches the Python reference implementation in wyze_scale_tool by JesusFreke,
 * which also processes one 8-byte block at a time.
 *
 * Reference: https://en.wikipedia.org/wiki/XXTEA
 * Reference: https://github.com/JesusFreke/wyze_scale_tool
 */
package com.health.openscale.core.bluetooth.libs

object XxteaLib {

    private const val DELTA = 0x9E3779B9L // unsigned

    /* ---- Low-level block operations ---- */

    /**
     * Encrypts a single 8-byte block with the given 16-byte key.
     *
     * @param block  8-byte plaintext block.
     * @param key    16-byte key.
     * @return       8-byte ciphertext block.
     */
    fun encrypt(block: ByteArray, key: ByteArray): ByteArray {
        require(block.size == 8) { "Block must be exactly 8 bytes" }
        require(key.size == 16) { "Key must be exactly 16 bytes" }

        val v = block.toUIntArray()   // v[0], v[1] – the two 32-bit words
        val k = key.toKeyArray()      // k[0..3] – four 32-bit key words

        val n = 2
        val rounds = 32
        var sum = 0L

        for (i in 0 until rounds) {
            sum = (sum + DELTA) and 0xFFFFFFFFL
            val e = (sum ushr 2) and 3L
            // Update v[0]
            v[0] = ((v[0] + ((((v[1] shl 4) xor (v[1] ushr 5)) + v[1]) xor (sum + k[(e).toInt()]))) and 0xFFFFFFFFL)
            // Update v[1]
            v[1] = ((v[1] + ((((v[0] shl 4) xor (v[0] ushr 5)) + v[0]) xor ((sum + k[(e xor 1L).toInt()]))) ) and 0xFFFFFFFFL)
        }

        return v.toByteArray()
    }

    /**
     * Decrypts a single 8-byte block with the given 16-byte key.
     *
     * @param block  8-byte ciphertext block.
     * @param key    16-byte key.
     * @return       8-byte plaintext block.
     */
    fun decrypt(block: ByteArray, key: ByteArray): ByteArray {
        require(block.size == 8) { "Block must be exactly 8 bytes" }
        require(key.size == 16) { "Key must be exactly 16 bytes" }

        val v = block.toUIntArray()
        val k = key.toKeyArray()

        val rounds = 32
        var sum = (DELTA * rounds) and 0xFFFFFFFFL

        for (i in 0 until rounds) {
            val e = (sum ushr 2) and 3L
            // Undo v[1]
            v[1] = ((v[1] - ((((v[0] shl 4) xor (v[0] ushr 5)) + v[0]) xor ((sum + k[(e xor 1L).toInt()])))) and 0xFFFFFFFFL)
            // Undo v[0]
            v[0] = ((v[0] - ((((v[1] shl 4) xor (v[1] ushr 5)) + v[1]) xor (sum + k[(e).toInt()]))) and 0xFFFFFFFFL)
            sum = (sum - DELTA) and 0xFFFFFFFFL
        }

        return v.toByteArray()
    }

    /* ---- Message-level operations (multi-block) ---- */

    /**
     * Encrypt an arbitrary-length payload.
     *
     * The payload is zero-padded to the next multiple of 8 bytes, then each 8-byte
     * block is encrypted independently.
     *
     * @param plaintext Payload to encrypt (any length).
     * @param key       16-byte key.
     * @return          Ciphertext (length rounded up to multiple of 8).
     */
    fun encryptMessage(plaintext: ByteArray, key: ByteArray): ByteArray {
        require(key.size == 16) { "Key must be exactly 16 bytes" }

        val padded = pad8(plaintext)
        val out = ByteArray(padded.size)
        for (i in 0 until padded.size / 8) {
            val enc = encrypt(padded.copyOfRange(i * 8, i * 8 + 8), key)
            enc.copyInto(out, i * 8)
        }
        return out
    }

    /**
     * Decrypt a multi-block ciphertext and return only the original payload bytes.
     *
     * @param ciphertext    Encrypted data; must be a multiple of 8 bytes.
     * @param key           16-byte key.
     * @param payloadLength Number of valid bytes in the decrypted result.
     * @return              First [payloadLength] bytes of the decrypted plaintext.
     */
    fun decryptMessage(ciphertext: ByteArray, key: ByteArray, payloadLength: Int): ByteArray {
        require(key.size == 16) { "Key must be exactly 16 bytes" }
        require(ciphertext.size % 8 == 0) { "Ciphertext length must be a multiple of 8" }

        val out = ByteArray(ciphertext.size)
        for (i in 0 until ciphertext.size / 8) {
            val dec = decrypt(ciphertext.copyOfRange(i * 8, i * 8 + 8), key)
            dec.copyInto(out, i * 8)
        }
        return out.copyOf(payloadLength)
    }

    /* ---- Private helpers ---- */

    /** Pad [data] to the next multiple of 8 bytes with zero bytes. */
    private fun pad8(data: ByteArray): ByteArray {
        val rem = data.size % 8
        return if (rem == 0) data else data + ByteArray(8 - rem)
    }

    /**
     * Parse 2 little-endian uint32 words from an 8-byte array into a [LongArray].
     * Values are stored as Long to stay unsigned in Kotlin.
     */
    private fun ByteArray.toUIntArray(): LongArray {
        val v = LongArray(2)
        for (i in v.indices) {
            v[i] = (this[i * 4 + 0].toLong() and 0xFFL) or
                   ((this[i * 4 + 1].toLong() and 0xFFL) shl 8) or
                   ((this[i * 4 + 2].toLong() and 0xFFL) shl 16) or
                   ((this[i * 4 + 3].toLong() and 0xFFL) shl 24)
        }
        return v
    }

    /**
     * Parse 4 little-endian uint32 words from a 16-byte key into a [LongArray].
     * Values are stored as Long to stay unsigned.
     */
    private fun ByteArray.toKeyArray(): LongArray {
        val k = LongArray(4)
        for (i in k.indices) {
            k[i] = (this[i * 4 + 0].toLong() and 0xFFL) or
                   ((this[i * 4 + 1].toLong() and 0xFFL) shl 8) or
                   ((this[i * 4 + 2].toLong() and 0xFFL) shl 16) or
                   ((this[i * 4 + 3].toLong() and 0xFFL) shl 24)
        }
        return k
    }

    /** Serialize a 2-element [LongArray] of uint32 words back to 8 LE bytes. */
    private fun LongArray.toByteArray(): ByteArray {
        val b = ByteArray(8)
        for (i in indices) {
            b[i * 4 + 0] = (this[i] and 0xFFL).toByte()
            b[i * 4 + 1] = ((this[i] ushr 8) and 0xFFL).toByte()
            b[i * 4 + 2] = ((this[i] ushr 16) and 0xFFL).toByte()
            b[i * 4 + 3] = ((this[i] ushr 24) and 0xFFL).toByte()
        }
        return b
    }
}
