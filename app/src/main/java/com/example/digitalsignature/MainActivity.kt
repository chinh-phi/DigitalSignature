package com.example.digitalsignature

import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.example.digitalsignature.cipher.RSACipher
import com.example.digitalsignature.key.RSAKeyGenerator
import com.example.digitalsignature.key.RSAKeypair
import java.security.SecureRandom
import java.util.Base64


class MainActivity : AppCompatActivity() {
    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        findViewById<Button>(R.id.button).setOnClickListener {
            val keyPairGenerator = RSAKeyGenerator()
            keyPairGenerator.initialize(3072, SecureRandom())
            val key: RSAKeypair = keyPairGenerator.generateKeyPair()

            val privateKey: String = Base64.getEncoder().encodeToString(key.privateKey.encoded)
            val publicKey: String = Base64.getEncoder().encodeToString(key.publicKey.encoded)

//            findViewById<TextView>(R.id.privateKey).text = privateKey
//            findViewById<TextView>(R.id.publicKey).text = publicKey

            val cipher = RSACipher()
            val plainText = findViewById<EditText>(R.id.message).text.toString()
            val cipherTextBytes = cipher.encrypt(plainText.toByteArray(), key.publicKey)
//            val cipherTextBytes = cipher.encryptOAEP(plainText.toByteArray(), "label".toByteArray(), key.publicKey)
            val plainTextBytes = cipher.decrypt(cipherTextBytes, key.privateKey)
//            val plainTextBytes = cipher.decryptOAEP(cipherTextBytes, "label".toByteArray(), key.privateKey)
            val result = String(plainTextBytes)
            findViewById<TextView>(R.id.text_decrypted).text = result
        }
    }

    companion object {
        private const val textToEncrypt = "Hello"
    }
}