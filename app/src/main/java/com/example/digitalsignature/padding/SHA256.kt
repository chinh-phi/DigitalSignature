package com.example.digitalsignature.padding

import java.nio.ByteBuffer

import java.util.Arrays


class SHA256 {
    private lateinit var data: ByteArray //Input data and padded data
    private lateinit var padded: ByteArray //Padded data
    private var blocks = 0 //Number of 512-bit blocks in padded data
    private lateinit var m: Array<IntArray> //Each padded data block represented as 32-bit integers
    private val w = IntArray(64) //Message schedule
    private val k = IntArray(64) //32-bit pre-defined constants

    //The eight hash values
    private var h0 = 0
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0
    private var h5 = 0
    private var h6 = 0
    private var h7 = 0
    private fun initConstants() { //Initializes constants
        k[0] = 0x428a2f98
        k[1] = 0x71374491
        k[2] = -0x4a3f0431
        k[3] = -0x164a245b
        k[4] = 0x3956c25b
        k[5] = 0x59f111f1
        k[6] = -0x6dc07d5c
        k[7] = -0x54e3a12b
        k[8] = -0x27f85568
        k[9] = 0x12835b01
        k[10] = 0x243185be
        k[11] = 0x550c7dc3
        k[12] = 0x72be5d74
        k[13] = -0x7f214e02
        k[14] = -0x6423f959
        k[15] = -0x3e640e8c
        k[16] = -0x1b64963f
        k[17] = -0x1041b87a
        k[18] = 0x0fc19dc6
        k[19] = 0x240ca1cc
        k[20] = 0x2de92c6f
        k[21] = 0x4a7484aa
        k[22] = 0x5cb0a9dc
        k[23] = 0x76f988da
        k[24] = -0x67c1aeae
        k[25] = -0x57ce3993
        k[26] = -0x4ffcd838
        k[27] = -0x40a68039
        k[28] = -0x391ff40d
        k[29] = -0x2a586eb9
        k[30] = 0x06ca6351
        k[31] = 0x14292967
        k[32] = 0x27b70a85
        k[33] = 0x2e1b2138
        k[34] = 0x4d2c6dfc
        k[35] = 0x53380d13
        k[36] = 0x650a7354
        k[37] = 0x766a0abb
        k[38] = -0x7e3d36d2
        k[39] = -0x6d8dd37b
        k[40] = -0x5d40175f
        k[41] = -0x57e599b5
        k[42] = -0x3db47490
        k[43] = -0x3893ae5d
        k[44] = -0x2e6d17e7
        k[45] = -0x2966f9dc
        k[46] = -0xbf1ca7b
        k[47] = 0x106aa070
        k[48] = 0x19a4c116
        k[49] = 0x1e376c08
        k[50] = 0x2748774c
        k[51] = 0x34b0bcb5
        k[52] = 0x391c0cb3
        k[53] = 0x4ed8aa4a
        k[54] = 0x5b9cca4f
        k[55] = 0x682e6ff3
        k[56] = 0x748f82ee
        k[57] = 0x78a5636f
        k[58] = -0x7b3787ec
        k[59] = -0x7338fdf8
        k[60] = -0x6f410006
        k[61] = -0x5baf9315
        k[62] = -0x41065c09
        k[63] = -0x398e870e
    }

    private fun initHashValues() { //Initializes hash values
        h0 = 0x6a09e667
        h1 = -0x4498517b
        h2 = 0x3c6ef372
        h3 = -0x5ab00ac6
        h4 = 0x510e527f
        h5 = -0x64fa9774
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19
    }

    private fun padding() { //Pads data
        //Pads a single '1' bit and k '0' bits, where 1 + k + length (in bits) ≡ 448 (mod 512)
        if (data.size % 64 < 56) {
            padded = Arrays.copyOf(data, 64 * (data.size / 64 + 1))
            padded[data.size] = 128.toByte()
        } else {
            padded = Arrays.copyOf(data, 64 * (data.size / 64 + 2))
            padded[data.size] = 128.toByte()
        }
        //Pads a 64-bit binary representation of the length of the data in bits
        val data_size = (data.size * 8).toLong() //Size of data in bits;
        val data_size_bytes =
            ByteBuffer.allocate(8).putLong(data_size).array() //data_size as byte array
        System.arraycopy(data_size_bytes, 0, padded, padded.size - 8, data_size_bytes.size)
    }

    private fun parsing() { //Converts each data block to 32-bit integers
        blocks = padded.size / 64
        m = Array(blocks) { IntArray(16) }
        val word = ByteArray(4) //32-bit word
        var word_index = 0
        for (i in 0 until blocks) {
            for (j in 0..15) {
                System.arraycopy(padded, word_index, word, 0, 4)
                m[i][j] = ByteBuffer.wrap(word).int
                word_index += 4
            }
        }
    }

    fun digest(input: ByteArray): ByteArray { //Computes message digest
        data = input
        initHashValues()
        padding()
        parsing()

        //The eight working values
        var a: Int
        var b: Int
        var c: Int
        var d: Int
        var e: Int
        var f: Int
        var g: Int
        var h: Int

        //Temporary variables
        var t1: Int
        var t2: Int
        for (i in 0 until blocks) {
            //Prepares message schedule
            for (t in 0..63) {
                if (t <= 15) {
                    w[t] = m[i][t]
                } else {
                    w[t] =
                        l_sigma1(w[t - 2]) + w[t - 7] + l_sigma0(w[t - 15]) + w[t - 16]
                }
            }
            //Initializes working variables
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = h5
            g = h6
            h = h7
            for (t in 0..63) {
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
            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
            h5 += f
            h6 += g
            h7 += h
        }

        //Prepares message digest as a 256-bit byte array
        val buffer = ByteBuffer.allocate(32)
        buffer.putInt(h0)
        buffer.putInt(h1)
        buffer.putInt(h2)
        buffer.putInt(h3)
        buffer.putInt(h4)
        buffer.putInt(h5)
        buffer.putInt(h6)
        buffer.putInt(h7)
        return buffer.array()
    }

    private fun rotateRight(
        x: Int,
        n: Int
    ): Int { //Circular right shift (x: Integer, n: Shift value)
        return x ushr n or (x shl 32 - n)
    }

    //SHA-256 Functions
    private fun ch(x: Int, y: Int, z: Int): Int {
        return x and y xor (x.inv() and z)
    }

    private fun maj(x: Int, y: Int, z: Int): Int {
        return x and y xor (x and z) xor (y and z)
    }

    private fun sigma0(x: Int): Int {
        return rotateRight(x, 2) xor rotateRight(x, 13) xor rotateRight(x, 22)
    }

    private fun sigma1(x: Int): Int {
        return rotateRight(x, 6) xor rotateRight(x, 11) xor rotateRight(x, 25)
    }

    private fun l_sigma0(x: Int): Int {
        return rotateRight(x, 7) xor rotateRight(x, 18) xor (x ushr 3)
    }

    private fun l_sigma1(x: Int): Int {
        return rotateRight(x, 17) xor rotateRight(x, 19) xor (x ushr 10)
    }

    init {
        initConstants()
    }
}
