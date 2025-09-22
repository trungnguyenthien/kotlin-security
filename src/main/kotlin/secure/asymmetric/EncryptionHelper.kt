package tx.secure.asymmetric

import tx.secure.type.KeyPair
import tx.secure.type.Result

// Interface for asymmetric encryption and decryption
interface EncryptionHelper {
    // Generate a new asymmetric key pair
    @Throws(Exception::class)
    fun generateKeyPair(): KeyPair

    // Encrypt plaintext using the recipient's public key
    @Throws(Exception::class)
    fun encrypt(plaintext: String, base64RecipientPublicKey: String): Result

    // Decrypt the encrypted JSON using the recipient's private key and the ephemeral public key
    @Throws(Exception::class)
    fun decrypt(encryptedJson: String, base64EphemeralPublicKey: String, base64RecipientPrivateKey: String): String
}