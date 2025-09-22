package tx.secure.asymmetric

import org.bouncycastle.jce.provider.BouncyCastleProvider
import tx.secure.type.KeyPair
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

/**
 * Provides digital signature utilities using Ed25519 algorithm.
 */
class SignatureHelperV1 : SignatureHelper {
    private val provider = "BC" // Bouncy Castle
    private val algorithm = "Ed25519"

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    /**
     * Generates an Ed25519 key pair for signing and verifying.
     *
     * @return KeyPair containing both key objects and Base64 strings
     */
    @Throws(Exception::class)
    override fun generateKeyPair(): tx.secure.type.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider)
        val pair = keyPairGenerator.generateKeyPair()
        return KeyPair(pair.public, pair.private)
    }

    /**
     * Signs a string using the provided private key.
     *
     * @param data       plaintext string
     * @param privateKey Base64-encoded private key
     * @return Base64-encoded signature
     */
    @Throws(Exception::class)
    override fun sign(data: String, privateKey: String): String {
        return sign(data.toByteArray(), privateKey)
    }

    /**
     * Signs a byte array using the provided private key.
     *
     * @param data       plaintext byte array
     * @param privateKey Base64-encoded private key
     * @return Base64-encoded signature
     */
    @Throws(Exception::class)
    override fun sign(data: ByteArray, privateKey: String): String {
        val privKey = decodePrivateKey(privateKey)
        val signature = Signature.getInstance(algorithm, provider)
        signature.initSign(privKey)
        signature.update(data)
        val signed = signature.sign()
        return Base64.getEncoder().encodeToString(signed)
    }

    /**
     * Verifies a string against a Base64-encoded signature using the provided public key.
     *
     * @param data      plaintext string
     * @param signature Base64-encoded signature
     * @param publicKey Base64-encoded public key
     * @return true if valid, false otherwise
     */
    @Throws(Exception::class)
    override fun verify(data: String, signature: String, publicKey: String): Boolean {
        return verify(data.toByteArray(), signature, publicKey)
    }

    /**
     * Verifies a byte array against a Base64-encoded signature using the provided public key.
     *
     * @param data      plaintext byte array
     * @param signature Base64-encoded signature
     * @param publicKey Base64-encoded public key
     * @return true if valid, false otherwise
     */
    @Throws(Exception::class)
    override fun verify(data: ByteArray, signature: String, publicKey: String): Boolean {
        val pubKey = decodePublicKey(publicKey)
        val sig = Signature.getInstance(algorithm, provider)
        sig.initVerify(pubKey)
        sig.update(data)
        val signatureBytes = Base64.getDecoder().decode(signature)
        return sig.verify(signatureBytes)
    }

    @Throws(Exception::class)
    private fun decodePublicKey(publicKey: String): PublicKey {
        val keyBytes = Base64.getDecoder().decode(publicKey)
        val spec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(algorithm, provider)
        return keyFactory.generatePublic(spec)
    }

    @Throws(Exception::class)
    private fun decodePrivateKey(privateKey: String): PrivateKey {
        val keyBytes = Base64.getDecoder().decode(privateKey)
        val spec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(algorithm, provider)
        return keyFactory.generatePrivate(spec)
    }
}