package tx.secure.asymmetric

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import tx.secure.type.KeyPair
import tx.secure.type.Result
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.KeyAgreement

/**
 * Provides encryption and decryption utilities using ECDH for key agreement
 * and AES for symmetric encryption.
 */
class EncryptionHelperV1(private val symmetricHelper: tx.secure.symmetric.EncryptionHelper) : EncryptionHelper {

    companion object {
        init {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class)
        private fun keyFactory(): KeyFactory {
            return KeyFactory.getInstance("ECDH", "BC")
        }
    }

    @Throws(Exception::class)
    override fun generateKeyPair(): tx.secure.type.KeyPair {
        val gen = KeyPairGenerator.getInstance("ECDH", "BC")
        gen.initialize(ECNamedCurveGenParameterSpec("secp256r1"))
        val kp = gen.generateKeyPair()
        return KeyPair(kp.public, kp.private)
    }

    @Throws(Exception::class)
    override fun encrypt(plaintext: String, base64RecipientPublicKey: String): Result {
        val recipientPublicKey = keyFactory()
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(base64RecipientPublicKey)))
        val ephemeral = generateKeyPair()
        val aesKey = deriveKey(ephemeral.private, recipientPublicKey)
        val tempResult = symmetricHelper.encrypt(plaintext, aesKey)
        val ephemeralPubKey = Base64.getEncoder().encodeToString(ephemeral.public.encoded)
        return Result(tempResult.alg, tempResult.iv, tempResult.ct, tempResult.tag, ephemeralPubKey)
    }

    @Throws(Exception::class)
    override fun decrypt(encryptedJson: String, base64EphemeralPublicKey: String, base64RecipientPrivateKey: String): String {
        val recipientPrivateKey = keyFactory()
            .generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64RecipientPrivateKey)))

        val ephemeralPublicKey = keyFactory()
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(base64EphemeralPublicKey)))

        val aesKey = deriveKey(recipientPrivateKey, ephemeralPublicKey)
        return symmetricHelper.decrypt(Result(encryptedJson), aesKey)
    }

    @Throws(Exception::class)
    private fun deriveKey(privateKey: PrivateKey, publicKey: PublicKey): String {
        val ka = KeyAgreement.getInstance("ECDH", "BC")
        ka.init(privateKey)
        ka.doPhase(publicKey, true)

        val shared = ka.generateSecret()
        val hash = MessageDigest.getInstance("SHA-256", "BC").digest(shared)
        return Base64.getEncoder().encodeToString(hash)
    }
}