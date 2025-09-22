package tx.secure.asymmetric

import tx.secure.type.KeyPair

// Interface for digital signature generation and verification
interface SignatureHelper {
    // Generate a new asymmetric key pair for signing and verification
    @Throws(Exception::class)
    fun generateKeyPair(): KeyPair

    // Sign the given data using the provided private key, returning the signature as a Base64 string
    @Throws(Exception::class)
    fun sign(data: String, privateKey: String): String

    // Sign the given byte array data using the provided private key, returning the signature as a Base64 string
    @Throws(Exception::class)
    fun sign(data: ByteArray, privateKey: String): String

    // Verify the given data against the provided Base64-encoded signature using the public key
    @Throws(Exception::class)
    fun verify(data: String, signature: String, publicKey: String): Boolean

    // Verify the given byte array data against the provided Base64-encoded signature using the public key
    @Throws(Exception::class)
    fun verify(data: ByteArray, signature: String, publicKey: String): Boolean
}