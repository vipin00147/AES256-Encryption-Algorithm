# AES256-Encryption-Algorithm
This is the basei code or encrypt and decrypt data the help of secret key

import android.util.Base64
import android.util.Log
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESEncryption {

    var keyGenerator: KeyGenerator? = null
    var secretKey: SecretKey? = null
    var secretKeyen: ByteArray ?= null
    var strSecretKey: String? = null
    var IV = ByteArray(16)
    var cipherText: ByteArray ?= null
    var random: SecureRandom? = null
    val myTag = "sfbsfhsdjfhsdkfsdjfhsdjkfhsdjkfhsdjkhfjksdfjksdfbsdnfdkfbsdkfsdfsjkdfsdjfsdjf"

    init {
        random = SecureRandom()
        random!!.nextBytes(IV)

        keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator?.init(256)
        secretKey = keyGenerator?.generateKey()
        secretKeyen = secretKey?.encoded
        strSecretKey = encoderFun(secretKeyen)
    }

    private fun encoderFun(decval: ByteArray?): String? {
        return Base64.encodeToString(decval, Base64.DEFAULT)
    }

    fun performOperation() {

        Log.e(myTag, "Secret Key : $strSecretKey")

        try {
            cipherText = encrypt("Hello Guys how are you".encodeToByteArray(), secretKey!!, IV)

            val encryptedText = encoderFun(IV)

            Log.e(myTag, "encryptedText : $encryptedText")
            Log.e(myTag, "IV : $IV")

            Log.e(myTag, "decryptedText : ${decrypt(cipherText, secretKey!!, IV)}")

        } catch (e: java.lang.Exception) {
            e.printStackTrace()
        }

    }

    private fun encrypt(plaintext: ByteArray?, key: SecretKey, IV: ByteArray?): ByteArray? {
        val cipher = Cipher.getInstance("AES")
        val keySpec = SecretKeySpec(key.encoded, "AES")
        val ivSpec = IvParameterSpec(IV)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(plaintext)
    }

    private fun decrypt(cipherText: ByteArray?, key: SecretKey, IV: ByteArray?): String? {
        try {
            val cipher = Cipher.getInstance("AES")
            val keySpec = SecretKeySpec(key.encoded, "AES")
            val ivSpec = IvParameterSpec(IV)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            val decryptedText = cipher.doFinal(cipherText)
            return String(decryptedText)
        } catch (e: java.lang.Exception) {
            e.printStackTrace()
        }
        return null
    }
}
