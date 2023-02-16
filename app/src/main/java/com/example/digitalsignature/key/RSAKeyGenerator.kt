package com.example.digitalsignature.key

import com.example.digitalsignature.key.PrimeGenerator.generatePrime
import java.math.BigInteger
import java.security.InvalidKeyException

import java.security.SecureRandom


class RSAKeyGenerator {
    private var publicExponent: BigInteger? = null

    // size of the key to generate, >= RSAKeyFactory.MIN_MODLEN
    private var keySize = 0
    private var random: SecureRandom? = null
    fun initialize(keysize: Int, random: SecureRandom?) {
        keySize = keysize
        publicExponent = BigInteger.valueOf(65537)
        this.random = random
    }

    fun generateKeyPair(): RSAKeypair {
        val lp = keySize + 1 shr 1
        val lq = keySize - lp
        if (random == null) {
            random = SecureRandom()
        }
        val e: BigInteger? = publicExponent
        while (true) {
            // generate two random primes of size lp/lq
            var p: BigInteger = generatePrime(lp)
            var q: BigInteger
            var n: BigInteger
            do {
                q = generatePrime(lq)
                // convention is for p > q
                if (p.compareTo(q) < 0) {
                    val tmp: BigInteger = p
                    p = q
                    q = tmp
                }
                // modulus n = p * q
                n = p.multiply(q)
                // even with correctly sized p and q, there is a chance that
                // n will be one bit short. re-generate the smaller prime if so
            } while (n.bitLength() < keySize)

            // phi = (p - 1) * (q - 1) must be relative prime to e
            // otherwise RSA just won't work ;-)
            val p1: BigInteger = p.subtract(BigInteger.ONE)
            val q1: BigInteger = q.subtract(BigInteger.ONE)
            val phi: BigInteger = p1.multiply(q1)
            // generate new p and q until they work. typically
            // the first try will succeed when using F4
            if (!e?.gcd(phi)?.equals(BigInteger.ONE)!!) {
                continue
            }

            // private exponent d is the inverse of e mod phi
            val d: BigInteger = e.modInverse(phi)
            var publicKey: RSAPublicKey? = null
            publicKey = try {
                RSAPublicKey(n, e)
            } catch (ex: InvalidKeyException) {
                throw RuntimeException(ex)
            }
            var privateKey: RSAPrivateKey? = null
            privateKey = try {
                RSAPrivateKey(n, d)
            } catch (ex: InvalidKeyException) {
                throw RuntimeException(ex)
            }
            return RSAKeypair(privateKey!!, publicKey!!)
        }
    }
}