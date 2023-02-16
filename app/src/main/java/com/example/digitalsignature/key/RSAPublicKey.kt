package com.example.digitalsignature.key

import java.io.IOException

import java.math.BigInteger

import java.security.InvalidKeyException
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence


class RSAPublicKey(modulus: BigInteger, exponent: BigInteger) {
    val modulus: BigInteger //RSA modulus
    val publicExponent: BigInteger //RSA public exponent

    //DER encoding of public key
    @get:Throws(IOException::class)
    val encoded: ByteArray
        get() { //DER encoding of public key
            val integers: Array<ASN1Integer> = arrayOf<ASN1Integer>(
                ASN1Integer(modulus), ASN1Integer(
                    publicExponent
                )
            )
            val sequence = DERSequence(integers)
            return sequence.encoded
        }

    init {
        if (exponent.compareTo(BigInteger.valueOf(3)) == -1 || exponent.compareTo(modulus) >= 0) {
            throw InvalidKeyException()
        }
        this.modulus = modulus
        publicExponent = exponent
    }
}