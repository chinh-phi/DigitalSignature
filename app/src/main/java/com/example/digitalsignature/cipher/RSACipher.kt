package com.example.digitalsignature.cipher

import com.example.digitalsignature.exception.InvalidDataException
import com.example.digitalsignature.key.RSAPrivateKey
import com.example.digitalsignature.key.RSAPublicKey
import com.example.digitalsignature.padding.SHA256
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Arrays
import kotlin.experimental.xor


class RSACipher {

    //RSA encryption
    fun encrypt(
        plainText: ByteArray?,
        publicKey: RSAPublicKey
    ): ByteArray {
        val message = BigInteger(plainText)
        val n = publicKey.modulus //RSA Modulus
        val e = publicKey.publicExponent //RSA Public Exponent
        if (message.compareTo(n) >= 0) {
            throw InvalidDataException()
        }
        return message.modPow(e, n).toByteArray()
    }

    fun decrypt(
        cipherText: ByteArray?,
        privateKey: RSAPrivateKey
    ): ByteArray { //RSA decryption
        val message = BigInteger(cipherText)
        val n = privateKey.modulus //RSA Modulus
        val d = privateKey.privateExponent //RSA Private Exponent
        if (message.compareTo(n) >= 0) {
            throw InvalidDataException()
        }
        return message.modPow(d, n).toByteArray()
    }

    private fun mgf(mgfSeed: ByteArray, maskLen: Int): ByteArray { //Mask generation function
        val t: ByteArray
        var buffer1: ByteBuffer
        val buffer2 = ByteBuffer.allocate(hLen * ((maskLen - 1) / hLen + 1))
        for (counter in 0 until (maskLen - 1) / hLen + 1) {
            buffer1 = ByteBuffer.allocate(mgfSeed.size + 4)
            buffer1.put(mgfSeed)
            buffer1.putInt(counter)
            buffer2.put(sha256.digest(buffer1.array()))
        }
        t = buffer2.array()
        val mask = ByteArray(maskLen)
        System.arraycopy(t, 0, mask, 0, maskLen)
        return mask
    }

    fun encryptOAEP(
        plainText: ByteArray,
        label: ByteArray,
        publicKey: RSAPublicKey
    ): ByteArray { //RSA-OAEP encryption
        val k: Int = if (publicKey.modulus.bitLength() % 8 > 0) {
            publicKey.modulus.bitLength() / 8 + 1
        } else {
            publicKey.modulus.bitLength() / 8
        } //Length of modulus in bytes
        if (plainText.size > k - 2 * hLen - 2) {
            throw InvalidDataException()
        }
        val lHash: ByteArray = sha256.digest(label)
        val ps = ByteArray(k - plainText.size - 2 * hLen - 2)
        var buffer = ByteBuffer.allocate(k - hLen - 1)
        buffer.put(lHash)
        buffer.put(ps)
        buffer.put(1.toByte())
        buffer.put(plainText)
        val db = buffer.array()
        val random = SecureRandom()
        val seed = ByteArray(hLen)
        random.nextBytes(seed)
        val dbMask = mgf(seed, k - hLen - 1)
        val maskedDB = ByteArray(k - hLen - 1)
        for (i in 0 until k - hLen - 1) {
            maskedDB[i] = (db[i] xor dbMask[i])
        }
        val seedMask = mgf(maskedDB, hLen)
        val maskedSeed = ByteArray(hLen)
        for (i in 0 until hLen) {
            maskedSeed[i] = (seed[i] xor seedMask[i])
        }
        buffer = ByteBuffer.allocate(k)
        buffer.put(0.toByte())
        buffer.put(maskedSeed)
        buffer.put(maskedDB)
        val em = buffer.array()
        return encrypt(em, publicKey)
    }

    fun decryptOAEP(
        cipherText: ByteArray,
        label: ByteArray,
        privateKey: RSAPrivateKey
    ): ByteArray { //RSA-OAEP decryption
        val k: Int = if (privateKey.modulus.bitLength() % 8 > 0) {
            privateKey.modulus.bitLength() / 8 + 1
        } else {
            privateKey.modulus.bitLength() / 8
        } //Length of modulus in bytes
        if (cipherText.size < k || cipherText.size > k + 1 || k < 2 * hLen + 2) {
            throw InvalidDataException()
        }
        val em = decrypt(cipherText, privateKey)
        val lHash: ByteArray = sha256.digest(label)
        val maskedSeed = ByteArray(hLen)
        val maskedDB = ByteArray(k - hLen - 1)
        if (em[0] == 0.toByte()) {
            System.arraycopy(em, 1, maskedSeed, 0, hLen)
            System.arraycopy(em, hLen + 1, maskedDB, 0, k - hLen - 1)
        } else {
            System.arraycopy(em, 0, maskedSeed, 0, hLen)
            System.arraycopy(em, hLen, maskedDB, 0, k - hLen - 1)
        }
        val seedMask = mgf(maskedDB, hLen)
        val seed = ByteArray(hLen)
        for (i in 0 until hLen) {
            seed[i] = (maskedSeed[i] xor seedMask[i])
        }
        val dbMask = mgf(seed, k - hLen - 1)
        val db = ByteArray(k - hLen - 1)
        for (i in 0 until k - hLen - 1) {
            db[i] = (maskedDB[i] xor dbMask[i])
        }
        val lHashInput = ByteArray(hLen)
        System.arraycopy(db, 0, lHashInput, 0, hLen)
        require(Arrays.equals(lHash, lHashInput))
        var mIndex = 0
        when (db[hLen]) {
            1.toByte() -> mIndex = hLen + 1
            0.toByte() -> {
                var i = hLen
                while (i < k - hLen - 1) {
                    if (db[i] == 1.toByte() && db[i - 1] == 0.toByte()) {
                        mIndex = i + 1
                        break
                    }
                    i++
                }
                require(mIndex != 0)
            }
            else -> throw IllegalArgumentException()
        }
        val plainText = ByteArray(db.size - mIndex)
        System.arraycopy(db, mIndex, plainText, 0, plainText.size)
        return plainText
    }

    companion object {
        private val sha256: SHA256 = SHA256()
        private val hLen = 32
    }
}