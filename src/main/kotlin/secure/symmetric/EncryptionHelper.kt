package tx.secure.symmetric

import tx.secure.type.Result

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