package com.example.digitalsignature.padding

import java.nio.ByteBuffer

import java.util.Arrays


class SHA512 {
    private lateinit var data: ByteArray //Input data and padded data
    private lateinit var padded: ByteArray //Padded data
    private var blocks //Number of 1024-bit blocks in padded data
            = 0
    private lateinit var m: Array<LongArray> //Each padded data block represented as 64-bit integers
    private val w = LongArray(80) //Message schedule
    private val k = LongArray(80) //64-bit pre-defined constants

    //The eight hash values
    var h0: Long = 0
    var h1: Long = 0
    var h2: Long = 0
    var h3: Long = 0
    var h4: Long = 0
    var h5: Long = 0
    var h6: Long = 0
    var h7: Long = 0
    private fun initConstants() {
        k[0] = 0x428a2f98d728ae22L
        k[1] = 0x7137449123ef65cdL
        k[2] = -0x4a3f043013b2c4d1L
        k[3] = -0x164a245a7e762444L
        k[4] = 0x3956c25bf348b538L
        k[5] = 0x59f111f1b605d019L
        k[6] = -0x6dc07d5b50e6b065L
        k[7] = -0x54e3a12a25927ee8L
        k[8] = -0x27f855675cfcfdbeL
        k[9] = 0x12835b0145706fbeL
        k[10] = 0x243185be4ee4b28cL
        k[11] = 0x550c7dc3d5ffb4e2L
        k[12] = 0x72be5d74f27b896fL
        k[13] = -0x7f214e01c4e9694fL
        k[14] = -0x6423f958da38edcbL
        k[15] = -0x3e640e8b3096d96cL
        k[16] = -0x1b64963e610eb52eL
        k[17] = -0x1041b879c7b0da1dL
        k[18] = 0x0fc19dc68b8cd5b5L
        k[19] = 0x240ca1cc77ac9c65L
        k[20] = 0x2de92c6f592b0275L
        k[21] = 0x4a7484aa6ea6e483L
        k[22] = 0x5cb0a9dcbd41fbd4L
        k[23] = 0x76f988da831153b5L
        k[24] = -0x67c1aead11992055L
        k[25] = -0x57ce3992d24bcdf0L
        k[26] = -0x4ffcd8376704dec1L
        k[27] = -0x40a680384110f11cL
        k[28] = -0x391ff40cc257703eL
        k[29] = -0x2a586eb86cf558dbL
        k[30] = 0x06ca6351e003826fL
        k[31] = 0x142929670a0e6e70L
        k[32] = 0x27b70a8546d22ffcL
        k[33] = 0x2e1b21385c26c926L
        k[34] = 0x4d2c6dfc5ac42aedL
        k[35] = 0x53380d139d95b3dfL
        k[36] = 0x650a73548baf63deL
        k[37] = 0x766a0abb3c77b2a8L
        k[38] = -0x7e3d36d1b812511aL
        k[39] = -0x6d8dd37aeb7dcac5L
        k[40] = -0x5d40175eb30efc9cL
        k[41] = -0x57e599b443bdcfffL
        k[42] = -0x3db4748f2f07686fL
        k[43] = -0x3893ae5cf9ab41d0L
        k[44] = -0x2e6d17e62910ade8L
        k[45] = -0x2966f9dbaa9a56f0L
        k[46] = -0xbf1ca7aa88edfd6L
        k[47] = 0x106aa07032bbd1b8L
        k[48] = 0x19a4c116b8d2d0c8L
        k[49] = 0x1e376c085141ab53L
        k[50] = 0x2748774cdf8eeb99L
        k[51] = 0x34b0bcb5e19b48a8L
        k[52] = 0x391c0cb3c5c95a63L
        k[53] = 0x4ed8aa4ae3418acbL
        k[54] = 0x5b9cca4f7763e373L
        k[55] = 0x682e6ff3d6b2b8a3L
        k[56] = 0x748f82ee5defb2fcL
        k[57] = 0x78a5636f43172f60L
        k[58] = -0x7b3787eb5e0f548eL
        k[59] = -0x7338fdf7e59bc614L
        k[60] = -0x6f410005dc9ce1d8L
        k[61] = -0x5baf9314217d4217L
        k[62] = -0x41065c084d3986ebL
        k[63] = -0x398e870d1c8dacd5L
        k[64] = -0x35d8c13115d99e64L
        k[65] = -0x2e794738de3f3df9L
        k[66] = -0x15258229321f14e2L
        k[67] = -0xa82b08011912e88L
        k[68] = 0x06f067aa72176fbaL
        k[69] = 0x0a637dc5a2c898a6L
        k[70] = 0x113f9804bef90daeL
        k[71] = 0x1b710b35131c471bL
        k[72] = 0x28db77f523047d84L
        k[73] = 0x32caab7b40c72493L
        k[74] = 0x3c9ebe0a15c9bebcL
        k[75] = 0x431d67c49c100d4cL
        k[76] = 0x4cc5d4becb3e42b6L
        k[77] = 0x597f299cfc657e2aL
        k[78] = 0x5fcb6fab3ad6faecL
        k[79] = 0x6c44198c4a475817L
    }

    private fun initHashValues() {
        h0 = 0x6a09e667f3bcc908L
        h1 = -0x4498517a7b3558c5L
        h2 = 0x3c6ef372fe94f82bL
        h3 = -0x5ab00ac5a0e2c90fL
        h4 = 0x510e527fade682d1L
        h5 = -0x64fa9773d4c193e1L
        h6 = 0x1f83d9abfb41bd6bL
        h7 = 0x5be0cd19137e2179L
    }

    private fun padding() { //Pads data
        //Pads a single '1' bit and k '0' bits, where 1 + k + length (in bits) ≡ 896 (mod 512)
        if (data.size % 128 < 112) {
            padded = Arrays.copyOf(data, 128 * (data.size / 128 + 1))
            padded[data.size] = 128.toByte()
        } else {
            padded = Arrays.copyOf(data, 128 * (data.size / 128 + 2))
            padded[data.size] = 128.toByte()
        }
        //Pads a 128-bit binary representation of the length of the data in bits
        val data_size = (data.size * 8).toLong() //Size of data in bits
        val data_size_bytes =
            ByteBuffer.allocate(8).putLong(data_size).array() //data_size as byte array
        System.arraycopy(data_size_bytes, 0, padded, padded.size - 8, data_size_bytes.size)
    }

    private fun parsing() { //Converts each data block to 32-bit integers
        blocks = padded.size / 128
        m = Array(blocks) { LongArray(16) }
        val word = ByteArray(8) //64-bit word
        var word_index = 0
        for (i in 0 until blocks) {
            for (j in 0..15) {
                System.arraycopy(padded, word_index, word, 0, 8)
                m[i][j] = ByteBuffer.wrap(word).long
                word_index += 8
            }
        }
    }

    fun digest(input: ByteArray): ByteArray { //Computes message digest
        data = input
        initHashValues()
        padding()
        parsing()

        //The eight working variables
        var a: Long
        var b: Long
        var c: Long
        var d: Long
        var e: Long
        var f: Long
        var g: Long
        var h: Long

        //Temporary variables
        var t1: Long
        var t2: Long
        for (i in 0 until blocks) {
            //Prepares message schedule
            for (t in 0..79) {
                if (t <= 15) {
                    w[t] = m[i][t]
                } else {
                    w[t] =
                        l_sigma1(w[t - 2]) + w[t - 7] + l_sigma0(w[t - 15]) + w[t - 16]
                }
            }

            //Initialize working variables
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = h5
            g = h6
            h = h7
            for (t in 0..79) {
                t1 = h + sigma1(e) + ch(e, f, g) + k[t] + w[t]
                t2 = sigma0(a) + maj(a, b, c)
                h = g
                g = f
                f = e
                e = d + t1
                d = c
                c = b
                b = a
                a = t1 + t2
            }

            //Final hash values for block
            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
            h5 += f
            h6 += g
            h7 += h
        }

        //Prepares message digest as a single 512-bit byte array
        val buffer = ByteBuffer.allocate(64)
        buffer.putLong(h0)
        buffer.putLong(h1)
        buffer.putLong(h2)
        buffer.putLong(h3)
        buffer.putLong(h4)
        buffer.putLong(h5)
        buffer.putLong(h6)
        buffer.putLong(h7)
        return buffer.array()
    }

    private fun rotateRight(
        x: Long,
        n: Int
    ): Long { //Circular right shift (x: Integer, n: Shift value)
        return x ushr n or (x shl 64 - n)
    }

    //SHA-512 Functions
    private fun ch(x: Long, y: Long, z: Long): Long {
        return x and y xor (x.inv() and z)
    }

    private fun maj(x: Long, y: Long, z: Long): Long {
        return x and y xor (x and z) xor (y and z)
    }

    private fun sigma0(x: Long): Long {
        return rotateRight(x, 28) xor rotateRight(x, 34) xor rotateRight(x, 39)
    }

    private fun sigma1(x: Long): Long {
        return rotateRight(x, 14) xor rotateRight(x, 18) xor rotateRight(x, 41)
    }

    private fun l_sigma0(x: Long): Long {
        return rotateRight(x, 1) xor rotateRight(x, 8) xor (x ushr 7)
    }

    private fun l_sigma1(x: Long): Long {
        return rotateRight(x, 19) xor rotateRight(x, 61) xor (x ushr 6)
    }

    init {
        initConstants()
    }
}