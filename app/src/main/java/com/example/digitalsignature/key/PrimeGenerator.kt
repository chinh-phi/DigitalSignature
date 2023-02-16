package com.example.digitalsignature.key

import java.math.BigInteger
import java.util.Random


object PrimeGenerator {
    private val RANDOM: Random = Random()
    fun generatePrime(bitLength: Int): BigInteger {
        var p: BigInteger
        do {
            p = BigInteger(bitLength, RANDOM)
        } while (!isProbablePrime(p, bitLength))
        return p
    }

    private fun isProbablePrime(n: BigInteger, bitLength: Int): Boolean {
        if (n.compareTo(BigInteger.valueOf(2)) < 0) {
            return false
        }
        var s = 0
        var d = n.subtract(BigInteger.ONE)
        while (!d.testBit(0)) {
            s++
            d = d.divide(BigInteger.valueOf(2))
        }
        for (i in 0 until bitLength / 4) {
            val a = randomInRange(BigInteger.valueOf(2), n.subtract(BigInteger.ONE))
            var x = a.modPow(d, n)
            if (x == BigInteger.ONE || x == n.subtract(BigInteger.ONE)) {
                continue
            }
            for (r in 0 until s) {
                x = x.modPow(BigInteger.valueOf(2), n)
                if (x == BigInteger.ONE) {
                    return false
                }
                if (x == n.subtract(BigInteger.ONE)) {
                    break
                }
            }
            if (x != n.subtract(BigInteger.ONE)) {
                return false
            }
        }
        return true
    }

    private fun randomInRange(min: BigInteger, max: BigInteger): BigInteger {
        val cmp = min.compareTo(max)
        if (cmp >= 0) {
            return min
        }
        val range = max.subtract(min)
        val length = range.bitLength()
        var result: BigInteger
        do {
            result = BigInteger(length, RANDOM)
        } while (result.compareTo(range) >= 0)
        return result.add(min)
    }
}