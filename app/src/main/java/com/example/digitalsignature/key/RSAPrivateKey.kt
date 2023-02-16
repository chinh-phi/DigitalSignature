package com.example.digitalsignature.key

import java.io.IOException

import java.math.BigInteger

import java.security.InvalidKeyException
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence


class RSAPrivateKey(modulus: BigInteger, exponent: BigInteger) {
    val modulus: BigInteger //RSA modulus
    val privateExponent: BigInteger //RSA private exponent

    //DER encoding of private key
    @get:Throws(IOException::class)
    val encoded: ByteArray
        get() { //DER encoding of private key
            val integers: Array<ASN1Integer> = arrayOf<ASN1Integer>(
                ASN1Integer(modulus), ASN1Integer(
                    privateExponent
                )
            )
            val sequence = DERSequence(integers)
            return sequence.encoded
        }

    init {
        if (exponent.compareTo(modulus) >= 0) {
            throw InvalidKeyException()
        }
        this.modulus = modulus
        privateExponent = exponent
    }
}