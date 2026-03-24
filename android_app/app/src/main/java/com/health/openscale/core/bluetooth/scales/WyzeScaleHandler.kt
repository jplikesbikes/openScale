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
 * Wyze Scale X (WL_SC3 / WHSCL1) handler.
 *
 * Protocol reference: https://github.com/JesusFreke/wyze_scale_tool
 * Issue: https://github.com/oliexdev/openScale/issues/853
 *
 * ## BLE identifiers
 *   Service   : 0000fd7b-0000-1000-8000-00805f9b34fb
 *   Char      : 00000001-0000-1000-8000-00805f9b34fb  (write + notify)
 *   Local name: "WL_SC3"
 *
 * ## Security
 *   - Diffie–Hellman key agreement  (base=5, mod=0xFFFFFFC5)
 *   - XXTEA block cipher, 8-byte blocks, 32 rounds, 16-byte key
 *   - XXTEA key = ASCII hex of 8-digit shared-key + 8 zero bytes
 *
 * ## Session flow (state machine)
 *   INIT
 *     → onConnected()  : subscribe notify, send DH public key (unencrypted)
 *   WAIT_KEY_EXCHANGE
 *     → scale returns its public key
 *     → derive shared key, build XXTEA key
 *     → send CMD_SYNC_TIME
 *   WAIT_SYNC_TIME_REPLY
 *     → scale replies success
 *     → send CMD_UPDATE_USER  (create/update user profile on the scale)
 *   WAIT_UPDATE_USER_REPLY
 *     → scale replies success
 *     → send CMD_CURRENT_USER_NEW  (select current user → triggers history stream)
 *   WAIT_SET_CURRENT_USER_REPLY
 *     → scale replies success
 *     → userInfo("waiting for measurement")
 *   COLLECTING_DATA
 *     → CMD_HISTORY_WEIGHT_DATA : parse + publish + send ack (ack causes scale to delete that record)
 *     → CMD_CUR_WEIGHT_DATA     : if measure_state == 2 (settled), parse + publish
 */
package com.health.openscale.core.bluetooth.scales

import com.health.openscale.R
import com.health.openscale.core.bluetooth.data.ScaleMeasurement
import com.health.openscale.core.bluetooth.data.ScaleUser
import com.health.openscale.core.bluetooth.libs.XxteaLib
import com.health.openscale.core.data.ActivityLevel
import com.health.openscale.core.data.GenderType
import com.health.openscale.core.service.ScannedDeviceInfo
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Date
import java.util.UUID

class WyzeScaleHandler : ScaleDeviceHandler() {

    // ─── BLE identifiers ──────────────────────────────────────────────────────

    private val WYZE_SERVICE = UUID.fromString("0000fd7b-0000-1000-8000-00805f9b34fb")
    private val WYZE_CHAR    = UUID.fromString("00000001-0000-1000-8000-00805f9b34fb")

    // ─── Wyze command bytes ───────────────────────────────────────────────────

    private val CMD_SYNC_TIME           = 0x01.toByte()
    private val CMD_UPDATE_USER         = 0x0A.toByte()
    private val CMD_DEL_USER            = 0x0B.toByte()
    private val CMD_CURRENT_USER_NEW    = 0x0E.toByte()
    private val CMD_HISTORY_WEIGHT_DATA = 0x09.toByte()
    private val CMD_CUR_WEIGHT_DATA     = 0x08.toByte()

    // 0xa8 companion byte present in every payload (likely a fixed "write" opcode)
    private val PAYLOAD_TAG = 0xa8.toByte()

    // ─── DH parameters (same as wyze_scale_tool) ─────────────────────────────

    private val DH_BASE     = BigInteger.valueOf(5)
    private val DH_MODULUS  = BigInteger("FFFFFFC5", 16)   // 0xFFFFFFC5

    // ─── Session state ────────────────────────────────────────────────────────

    private enum class State {
        INIT,
        WAIT_KEY_EXCHANGE,
        WAIT_SYNC_TIME_REPLY,
        WAIT_UPDATE_USER_REPLY,
        WAIT_SET_CURRENT_USER_REPLY,
        COLLECTING_DATA
    }

    private var state = State.INIT
    private var frameCounter = 0
    private var dhPrivateKey  = BigInteger.ZERO
    private var xxteaKey: ByteArray? = null

    // ─── supportFor ──────────────────────────────────────────────────────────

    override fun supportFor(device: ScannedDeviceInfo): DeviceSupport? {
        val nameMatch = device.name == "WL_SC3"
        val serviceMatch = WYZE_SERVICE in device.serviceUuids

        if (!nameMatch && !serviceMatch) return null

        return DeviceSupport(
            displayName = "Wyze Scale X",
            capabilities = setOf(
                DeviceCapability.TIME_SYNC,
                DeviceCapability.USER_SYNC,
                DeviceCapability.BODY_COMPOSITION,
                DeviceCapability.HISTORY_READ,
                DeviceCapability.LIVE_WEIGHT_STREAM
            ),
            implemented = setOf(
                DeviceCapability.TIME_SYNC,
                DeviceCapability.USER_SYNC,
                DeviceCapability.BODY_COMPOSITION,
                DeviceCapability.HISTORY_READ,
                DeviceCapability.LIVE_WEIGHT_STREAM
            ),
            linkMode = LinkMode.CONNECT_GATT
        )
    }

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    override fun onConnected(user: ScaleUser) {
        logI("Connected; starting key exchange")
        state = State.INIT
        frameCounter = 0
        xxteaKey = null

        setNotifyOn(WYZE_SERVICE, WYZE_CHAR)

        // Generate ephemeral DH keypair
        val random = SecureRandom()
        val privBytes = ByteArray(4)
        random.nextBytes(privBytes)
        dhPrivateKey = BigInteger(1, privBytes)                        // treat as unsigned
        val publicKey = DH_BASE.modPow(dhPrivateKey, DH_MODULUS).toLong() and 0xFFFFFFFFL

        // Key-exchange frame is NOT encrypted and uses raw frame counter (not +0x10)
        val frame = frameCounter++ and 0x0F
        val msg = ByteArray(12)
        msg[0] = frame.toByte()
        msg[1] = 0xf0.toByte()
        msg[2] = 0x00.toByte()
        msg[3] = 0x08.toByte()
        // Little-endian public key at bytes 4–7
        ByteBuffer.wrap(msg, 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(publicKey.toInt())
        // Bytes 8–11: zeroes (already zero from ByteArray constructor)

        logD("Sending DH public key: 0x${publicKey.toString(16)}")
        writeTo(WYZE_SERVICE, WYZE_CHAR, msg, withResponse = true)
        state = State.WAIT_KEY_EXCHANGE
    }

    override fun onDisconnected() {
        logI("Disconnected; resetting session state")
        state = State.INIT
        xxteaKey = null
    }

    // ─── Notification handler ─────────────────────────────────────────────────

    override fun onNotification(characteristic: UUID, data: ByteArray, user: ScaleUser) {
        if (data.isEmpty()) return

        val firstNibble = data[0].toInt() and 0xF0

        when {
            // Key-exchange reply: 0x4_ 0xF0 ...
            firstNibble == 0x40 && data.size >= 12 && data[1] == 0xf0.toByte() -> {
                handleKeyExchangeReply(data, user)
            }

            // Encrypted notification: 0x5_ 0x01 ...
            firstNibble == 0x50 && data.size >= 12 && data[1] == 0x01.toByte() -> {
                handleEncryptedNotification(data, user)
            }

            else -> {
                logD("Ignored notification: ${data.toHexPreview(8)}")
            }
        }
    }

    // ─── Key exchange ─────────────────────────────────────────────────────────

    private fun handleKeyExchangeReply(data: ByteArray, user: ScaleUser) {
        if (state != State.WAIT_KEY_EXCHANGE) {
            logW("Unexpected key-exchange reply in state $state")
            return
        }

        // Scale public key is bytes 4–7, little-endian
        val scalePublicKey = (ByteBuffer.wrap(data, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong()) and 0xFFFFFFFFL
        logD("Received scale DH public key: 0x${scalePublicKey.toString(16)}")

        val scalePublicKeyBig = BigInteger.valueOf(scalePublicKey)
        val sharedKey = scalePublicKeyBig.modPow(dhPrivateKey, DH_MODULUS).toLong() and 0xFFFFFFFFL

        // XXTEA key = ASCII bytes of the 8-char hex representation of sharedKey,
        // followed by 8 zero bytes, for a total of 16 bytes.
        val hexStr = "%08x".format(sharedKey)
        xxteaKey = ByteArray(16)
        hexStr.forEachIndexed { i, ch -> xxteaKey!![i] = ch.code.toByte() }

        logI("Encryption negotiated; shared key = 0x${sharedKey.toString(16)}")

        // Start the command sequence
        sendSyncTime()
        state = State.WAIT_SYNC_TIME_REPLY
    }

    // ─── Encrypted notification routing ──────────────────────────────────────

    private fun handleEncryptedNotification(data: ByteArray, user: ScaleUser) {
        val key = xxteaKey
        if (key == null) {
            logW("Received encrypted notification but XXTEA key not yet established")
            return
        }

        // Encrypted blocks start at byte 4; byte 3 = plaintext payload length
        if (data.size < 4) return
        val payloadLength = data[3].toInt() and 0xFF
        val ciphertext = data.copyOfRange(4, data.size)
        if (ciphertext.isEmpty() || ciphertext.size % 8 != 0) {
            logW("Malformed encrypted notification: ciphertext size ${ciphertext.size}")
            return
        }

        val decrypted = try {
            XxteaLib.decryptMessage(ciphertext, key, payloadLength)
        } catch (e: Exception) {
            logE("XXTEA decryption failed: ${e.message}", e)
            return
        }

        if (decrypted.size < 5) {
            logD("Decrypted payload too short (${decrypted.size}b)")
            return
        }

        // Validate header: 0x22 0x01 [length 2B LE] [cmd] 0xa8 [data...]
        if (decrypted[0] != 0x22.toByte() || decrypted[1] != 0x01.toByte()) {
            logD("Unexpected decrypted header: ${decrypted.toHexPreview(6)}")
            return
        }

        val cmd = decrypted[4]
        logD("Decrypted cmd=0x${cmd.toUByte().toString(16)} state=$state ${decrypted.toHexPreview(16)}")

        when (cmd) {
            CMD_SYNC_TIME           -> handleSyncTimeReply(decrypted, user)
            CMD_UPDATE_USER         -> handleUpdateUserReply(decrypted, user)
            CMD_CURRENT_USER_NEW    -> handleSetCurrentUserReply(decrypted, user)
            CMD_HISTORY_WEIGHT_DATA -> handleHistoricalWeightData(decrypted, user)
            CMD_CUR_WEIGHT_DATA     -> handleCurrentWeightData(decrypted, user)
            CMD_DEL_USER            -> logD("DeleteUser reply")
            else                    -> logD("Unhandled cmd=0x${cmd.toUByte().toString(16)}")
        }
    }

    // ─── Command sequence replies ─────────────────────────────────────────────

    private fun handleSyncTimeReply(decrypted: ByteArray, user: ScaleUser) {
        if (state != State.WAIT_SYNC_TIME_REPLY) return
        val success = decrypted.size >= 7 && decrypted[6] == 0x00.toByte()
        if (!success) { logW("SyncTime failed"); return }
        logI("Time synchronized; sending user profile")
        sendUpdateUser(user)
        state = State.WAIT_UPDATE_USER_REPLY
    }

    private fun handleUpdateUserReply(decrypted: ByteArray, user: ScaleUser) {
        if (state != State.WAIT_UPDATE_USER_REPLY) return
        val success = decrypted.size >= 7 && decrypted[6] == 0x00.toByte()
        if (!success) { logW("UpdateUser failed"); return }
        logI("User profile saved to scale; selecting as current user")
        sendCurrentUserNew(user)
        state = State.WAIT_SET_CURRENT_USER_REPLY
    }

    private fun handleSetCurrentUserReply(decrypted: ByteArray, user: ScaleUser) {
        if (state != State.WAIT_SET_CURRENT_USER_REPLY) return
        val success = decrypted.size >= 7 && decrypted[6] == 0x00.toByte()
        if (!success) { logW("SetCurrentUserNew failed"); return }
        logI("Current user set; awaiting measurements")
        state = State.COLLECTING_DATA
        userInfo(R.string.bt_info_waiting_for_measurement)
    }

    // ─── Weight data parsing ──────────────────────────────────────────────────

    /**
     * Parses a CMD_HISTORY_WEIGHT_DATA notification from the scale.
     *
     * After publication the scale is acknowledged (ACK causes the scale to delete
     * this record from its cache). If not acknowledged, the record reappears on next session.
     *
     * Payload layout (after decryption, byte offsets into [decrypted]):
     * ```
     *  0–1    0x22 0x01  (header)
     *  2–3    length (LE uint16)
     *  4      cmd = 0x09
     *  5      0xa8
     *  6      success (1 = yes)
     *  7–10   timestamp (uint32 LE, unix seconds)
     * 11–26   user_id (16 bytes)
     * 27      sex
     * 28      age
     * 29      height (cm)
     * 30      athlete_mode
     * 31      only_weight
     * 32–33   raw_weight   (uint16 LE, /100 = kg)
     * 34–35   impedance    (uint16 LE, Ω)
     * 36–37   bfp          (uint16 LE, /10 = %)
     * 38–39   muscleMass   (uint16 LE, /10 = kg)
     * 40      boneMass     (uint8,     /10 = kg)
     * 41–42   water        (uint16 LE, /10 = %)
     * 43–44   protein      (uint16 LE, /10 = % — not stored)
     * 45–46   lbm          (uint16 LE, /10 = kg)
     * 47      vfal         (uint8,  raw integer level)
     * 48–49   bmr          (uint16 LE, raw kcal)
     * 50      bodyAge      (uint8  — not stored)
     * 51–52   bmi          (uint16 LE, /10 — not stored)
     * ```
     * Total decrypted length = 53 bytes.
     */
    private fun handleHistoricalWeightData(decrypted: ByteArray, user: ScaleUser) {
        if (decrypted.size < 53) {
            logW("CMD_HISTORY_WEIGHT_DATA too short: ${decrypted.size}")
            sendHistoryAck()
            return
        }

        val success = decrypted[6] == 0x01.toByte()
        if (!success) {
            logW("CMD_HISTORY_WEIGHT_DATA success=false; no more cached records")
            return
        }

        val buf = ByteBuffer.wrap(decrypted).order(ByteOrder.LITTLE_ENDIAN)

        // Skip header (7 bytes)
        val timestamp  = buf.getInt(7).toLong() and 0xFFFFFFFFL
        // user_id bytes 11–26 (16 bytes) – used only for logging
        val rawWeight  = buf.getShort(32).toInt() and 0xFFFF
        val impedance  = buf.getShort(34).toInt() and 0xFFFF
        val bfp        = buf.getShort(36).toInt() and 0xFFFF
        val muscleMass = buf.getShort(38).toInt() and 0xFFFF
        val boneMass   = decrypted[40].toInt() and 0xFF
        val water      = buf.getShort(41).toInt() and 0xFFFF
        // protein at 43–44 – not stored
        val lbm        = buf.getShort(45).toInt() and 0xFFFF
        val vfal       = decrypted[47].toInt() and 0xFF
        val bmr        = buf.getShort(48).toInt() and 0xFFFF
        // bodyAge at 50 – not stored
        // bmi at 51–52  – not stored

        val weightKg   = rawWeight / 100f

        val measurement = ScaleMeasurement(
            userId   = user.id,
            dateTime = Date(timestamp * 1000L),
            weight   = weightKg,
            fat      = bfp / 10f,
            water    = water / 10f,
            muscle   = if (weightKg > 0f) (muscleMass / 10f) / weightKg * 100f else 0f,
            visceralFat = vfal.toFloat(),
            bone     = boneMass / 10f,
            lbm      = lbm / 10f,
            bmr      = bmr.toFloat(),
            impedance = impedance.toDouble()
        )

        logI("Historical weight: ${weightKg}kg fat=${bfp/10f}% water=${water/10f}%")
        publish(measurement)

        // ACK required so the scale removes this record from its cache.
        sendHistoryAck()
    }

    /**
     * Parses a CMD_CUR_WEIGHT_DATA (live weighing) notification.
     *
     * Payload layout (after decryption):
     * ```
     *  0–1    0x22 0x01
     *  2–3    length (LE)
     *  4      cmd = 0x08
     *  5      0xa8
     *  6      battery
     *  7      unit
     *  8–23   user_id (16 bytes)
     * 24      sex
     * 25      age
     * 26      height
     * 27      athlete_mode
     * 28      only_weight
     * 29      measure_state  (2 = weight settled / final)
     * 30–31   raw_weight     (uint16 LE, /100 = kg)
     * 32–33   impedance
     * 34–35   bfp
     * 36–37   muscleMass
     * 38      boneMass
     * 39–40   water
     * 41–42   protein
     * 43–44   lbm
     * 45      vfal
     * 46–47   bmr
     * 48      bodyAge
     * 49–50   bmi
     * ```
     * Total = 51 bytes.
     *
     * Only publish when measure_state == 2 (weight settled / final measurement).
     */
    private fun handleCurrentWeightData(decrypted: ByteArray, user: ScaleUser) {
        if (decrypted.size < 51) {
            logD("CMD_CUR_WEIGHT_DATA payload short: ${decrypted.size}")
            return
        }

        val measureState = decrypted[29].toInt() and 0xFF
        if (measureState != 2) {
            // Still stabilising – log but don't publish
            val buf = ByteBuffer.wrap(decrypted).order(ByteOrder.LITTLE_ENDIAN)
            val rawW = buf.getShort(30).toInt() and 0xFFFF
            logD("Live weight: ${rawW / 100f}kg (state=$measureState, not final)")
            return
        }

        val buf = ByteBuffer.wrap(decrypted).order(ByteOrder.LITTLE_ENDIAN)
        val rawWeight  = buf.getShort(30).toInt() and 0xFFFF
        val impedance  = buf.getShort(32).toInt() and 0xFFFF
        val bfp        = buf.getShort(34).toInt() and 0xFFFF
        val muscleMass = buf.getShort(36).toInt() and 0xFFFF
        val boneMass   = decrypted[38].toInt() and 0xFF
        val water      = buf.getShort(39).toInt() and 0xFFFF
        val lbm        = buf.getShort(43).toInt() and 0xFFFF
        val vfal       = decrypted[45].toInt() and 0xFF
        val bmr        = buf.getShort(46).toInt() and 0xFFFF

        val weightKg = rawWeight / 100f

        val measurement = ScaleMeasurement(
            userId    = user.id,
            dateTime  = Date(),
            weight    = weightKg,
            fat       = bfp / 10f,
            water     = water / 10f,
            muscle    = if (weightKg > 0f) (muscleMass / 10f) / weightKg * 100f else 0f,
            visceralFat = vfal.toFloat(),
            bone      = boneMass / 10f,
            lbm       = lbm / 10f,
            bmr       = bmr.toFloat(),
            impedance = impedance.toDouble()
        )

        logI("Final live weight: ${weightKg}kg")
        publish(measurement)
    }

    // ─── Commands sent to the scale ───────────────────────────────────────────

    /** Send CMD_SYNC_TIME with the current unix timestamp. */
    private fun sendSyncTime() {
        val now = (System.currentTimeMillis() / 1000L).toInt()
        // Payload = 0x16 0x00 [len=7 LE 2B] CMD_SYNC_TIME 0xa8 [timestamp 4B LE] 0x01
        val plain = ByteArray(11)
        plain[0] = 0x16
        plain[1] = 0x00
        plain[2] = 0x07  // length of cmd+data (1 + 1 + 4 + 1 = 7)
        plain[3] = 0x00
        plain[4] = CMD_SYNC_TIME
        plain[5] = PAYLOAD_TAG
        ByteBuffer.wrap(plain, 6, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(now)
        plain[10] = 0x01  // OS type: 0x01 = unix timestamp
        logD("CMD_SYNC_TIME ts=$now")
        sendEncrypted(plain)
    }

    /**
     * Send CMD_UPDATE_USER — creates or updates a user profile stored on the scale.
     *
     * Payload = header (6 bytes) + user data (25 bytes) = 31 bytes; length field = 0x1B = 27.
     */
    private fun sendUpdateUser(user: ScaleUser) {
        logD("CMD_UPDATE_USER userId=${user.id}")
        sendEncrypted(buildUserPayload(CMD_UPDATE_USER, user))
    }

    /**
     * Send CMD_CURRENT_USER_NEW — sets the active user and triggers the history stream.
     */
    private fun sendCurrentUserNew(user: ScaleUser) {
        logD("CMD_CURRENT_USER_NEW userId=${user.id}")
        sendEncrypted(buildUserPayload(CMD_CURRENT_USER_NEW, user))
    }

    /** Send the acknowledgement that causes the scale to mark the last history record as consumed. */
    private fun sendHistoryAck() {
        // Plaintext = 0x16 0x00 0x03 0x00 CMD_HISTORY 0xa8 0x00
        val plain = byteArrayOf(
            0x16, 0x00,
            0x03, 0x00,     // length = 3
            CMD_HISTORY_WEIGHT_DATA, PAYLOAD_TAG,
            0x00            // status = success
        )
        logD("Sending history ACK")
        sendEncrypted(plain)
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Build the 31-byte plaintext payload for [CMD_UPDATE_USER] or [CMD_CURRENT_USER_NEW].
     *
     * Layout:
     * ```
     * 0x16 0x00             (frame preamble bytes)
     * 0x1B 0x00             (payload length = 27 = 1 cmd + 1 tag + 25 user data)
     * [cmd]                 (CMD_UPDATE_USER or CMD_CURRENT_USER_NEW)
     * 0xa8                  (payload tag)
     * [user_id  16B]
     * [raw_weight 2B LE]    (stored last weight * 100; 0 if unknown)
     * [sex 1B]              (1 = male, 0 = female)
     * [age 1B]
     * [height 1B]           (cm, capped at 255)
     * [athlete 1B]          (1 if HEAVY or EXTREME activity level)
     * [only_weight 1B]      (always 0 – we want body composition)
     * [last_imp 2B LE]      (last known impedance value; 0 if unknown)
     * ```
     */
    private fun buildUserPayload(cmd: Byte, user: ScaleUser): ByteArray {
        val userId   = getUserIdFor(user)
        val lastMeas = lastMeasurementFor(user.id)
        val rawWeight = ((lastMeas?.weight ?: 0f) * 100).toInt().coerceIn(0, 0xFFFF)
        val lastImp   = lastMeas?.impedance?.toInt()?.coerceIn(0, 0xFFFF) ?: 0
        val sex       = if (user.gender == GenderType.MALE) 1 else 0
        val age       = user.age.coerceIn(0, 255)
        val height    = user.bodyHeight.toInt().coerceIn(0, 255)
        val athlete   = when (user.activityLevel) {
            ActivityLevel.HEAVY, ActivityLevel.EXTREME -> 1
            else -> 0
        }

        // 6 header bytes + 16 userId + 2 weight + 1 sex + 1 age + 1 height + 1 athlete + 1 only_weight + 2 imp = 31 total
        val plain = ByteArray(31)
        plain[0] = 0x16
        plain[1] = 0x00
        plain[2] = 0x1B   // length = 27
        plain[3] = 0x00
        plain[4] = cmd
        plain[5] = PAYLOAD_TAG
        userId.copyInto(plain, 6)                                                    // bytes 6–21
        ByteBuffer.wrap(plain, 22, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(rawWeight.toShort())
        plain[24] = sex.toByte()
        plain[25] = age.toByte()
        plain[26] = height.toByte()
        plain[27] = athlete.toByte()
        plain[28] = 0x00  // only_weight = 0 (always request body comp)
        ByteBuffer.wrap(plain, 29, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(lastImp.toShort())
        return plain
    }

    /**
     * Retrieve or create a stable 16-byte user ID for the given app user.
     *
     * The Wyze scale stores users keyed by their 16-byte UUID. We persist this UUID in
     * handler settings so the same app user maps to the same scale user across sessions.
     */
    private fun getUserIdFor(user: ScaleUser): ByteArray {
        val key = "wyze_uid_${user.id}"
        val stored = settingsGetString(key)
        if (stored != null && stored.length == 32) {
            return hexToBytes(stored)
        }
        // Generate a new random 16-byte ID
        val newId = ByteArray(16).also { SecureRandom().nextBytes(it) }
        settingsPutString(key, bytesToHex(newId))
        logI("Generated new Wyze user ID for appUser=${user.id}: ${bytesToHex(newId)}")
        return newId
    }

    /**
     * XXTEA-encrypt [plaintext] and write to the characteristic.
     *
     * Frame layout:
     * ```
     * byte[0] = (frameCounter++ % 16) + 0x10
     * byte[1] = 0x01
     * byte[2] = 0x00
     * byte[3] = plaintext length
     * byte[4+] = XXTEA-encrypted blocks (each 8 bytes)
     * ```
     */
    private fun sendEncrypted(plaintext: ByteArray) {
        val key = xxteaKey ?: run { logW("sendEncrypted: no XXTEA key yet"); return }
        val ciphertext = XxteaLib.encryptMessage(plaintext, key)

        val frame = (frameCounter++ and 0x0F) + 0x10
        val msg = ByteArray(4 + ciphertext.size)
        msg[0] = frame.toByte()
        msg[1] = 0x01
        msg[2] = 0x00
        msg[3] = plaintext.size.toByte()
        ciphertext.copyInto(msg, 4)

        writeTo(WYZE_SERVICE, WYZE_CHAR, msg, withResponse = true)
    }

    // ─── Utility ──────────────────────────────────────────────────────────────

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
