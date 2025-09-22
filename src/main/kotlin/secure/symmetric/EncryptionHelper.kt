package tx.secure.symmetric

import org.bouncycastle.jce.provider.BouncyCastleProvider
import tx.secure.Result
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.security.Security
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


interface EncryptionHelper {
    /**
     * Generate a random symmetric key and return it as Base64 encoded string
     */
    @Throws(Exception::class)
    fun generateKeyBase64(): String

    /**
     * Encrypt plaintext using the provided symmetric key
     */
    @Throws(Exception::class)
    fun encrypt(plaintext: String, keyBase64: String): Result

    /**
     * Decrypt the encrypted result using the provided symmetric key
     */
    @Throws(Exception::class)
    fun decrypt(result: Result, keyBase64: String): String
}

/**
 * SymmetricEncryptionHelperImpl - Implementation of SymmetricEncryptionHelper using AES-GCM-256 with Bouncy Castle
 * Random 12-byte (96-bit) IV
 */
class EncryptionHelperV1 : EncryptionHelper {
    companion object {
        private const val ALGORITHM = "AES"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val PROVIDER = "BC" // Bouncy Castle
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }

    init {
        // Add BouncyCastle provider if not already added
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /** Generate a random AES-256 key, returned as Base64 string */
    @Throws(Exception::class)
    override fun generateKeyBase64(): String {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER)
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()
        return Base64.getEncoder().encodeToString(secretKey.encoded)
    }

    /** Encrypt plaintext string -> EncryptResult */
    @Throws(Exception::class)
    override fun encrypt(plaintext: String, keyBase64: String): Result {
        val keyBytes = Base64.getDecoder().decode(keyBase64)
        val secretKey = SecretKeySpec(keyBytes, ALGORITHM)

        // Generate random IV
        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        val encryptedBytes = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))

        // Split encrypted data and tag
        val cipherText = ByteArray(encryptedBytes.size - GCM_TAG_LENGTH)
        val tag = ByteArray(GCM_TAG_LENGTH)
        System.arraycopy(encryptedBytes, 0, cipherText, 0, cipherText.size)
        System.arraycopy(encryptedBytes, cipherText.size, tag, 0, tag.size)

        return Result(
            "AES-GCM",
            Base64.getEncoder().encodeToString(iv),
            Base64.getEncoder().encodeToString(cipherText),
            Base64.getEncoder().encodeToString(tag),
            null
        )
    }

    /** Decrypt EncryptResult -> plaintext string */
    @Throws(Exception::class)
    override fun decrypt(result: Result, keyBase64: String): String {
        val keyBytes = Base64.getDecoder().decode(keyBase64)
        val secretKey = SecretKeySpec(keyBytes, ALGORITHM)

        val iv = Base64.getDecoder().decode(result.iv)
        val cipherText = Base64.getDecoder().decode(result.ct)
        val tag = Base64.getDecoder().decode(result.tag)

        // Combine ciphertext and tag
        val encryptedWithTag = ByteArray(cipherText.size + tag.size)
        System.arraycopy(cipherText, 0, encryptedWithTag, 0, cipherText.size)
        System.arraycopy(tag, 0, encryptedWithTag, cipherText.size, tag.size)

        val cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val decryptedBytes = cipher.doFinal(encryptedWithTag)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }
}