package com.example.digitalsignature.key

import java.math.BigInteger
import java.util.Random


object PrimeGenerator {
    // The Miller-Rabin test to check if a number is probably prime
    private fun isProbablyPrime(n: BigInteger, k: Int): Boolean {
        if (n.compareTo(BigInteger.ONE) == 0 || n.compareTo(BigInteger.valueOf(4)) == 0) {
            return true
        }
        if (n.mod(BigInteger.valueOf(2)).compareTo(BigInteger.ZERO) == 0) {
            return false
        }

        // Write n - 1 as 2^r * d
        var d = n.subtract(BigInteger.ONE)
        var r = 0
        while (d.mod(BigInteger.valueOf(2)).compareTo(BigInteger.ZERO) == 0) {
            r++
            d = d.divide(BigInteger.valueOf(2))
        }

        // Test k times
        for (i in 0 until k) {
            val a = randomBigInteger(BigInteger.valueOf(2), n.subtract(BigInteger.valueOf(2)))
            var x = a.modPow(d, n)
            if (x.compareTo(BigInteger.ONE) == 0 || x.compareTo(n.subtract(BigInteger.ONE)) == 0) {
                continue
            }
            for (j in 0 until r - 1) {
                x = x.modPow(BigInteger.valueOf(2), n)
                if (x.compareTo(BigInteger.ONE) == 0) {
                    return false
                }
                if (x.compareTo(n.subtract(BigInteger.ONE)) == 0) {
                    break
                }
            }
            if (x.compareTo(n.subtract(BigInteger.ONE)) != 0) {
                return false
            }
        }
        return true
    }

    // Generate a big prime number
    fun generatePrime(bitLength: Int): BigInteger? {
        var prime = BigInteger.ZERO
        val rand = Random()
        while (!isProbablyPrime(prime, 64)) {
            prime = BigInteger(bitLength, rand)
        }
        return prime
    }

    // A helper method to generate a random BigInteger between two values
    private fun randomBigInteger(min: BigInteger?, max: BigInteger): BigInteger {
        val range = max.subtract(min).add(BigInteger.ONE)
        return BigInteger(range.bitLength(), Random()).mod(range).add(min)
    }   
}