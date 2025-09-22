package tx.secure.type

import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64

/**
 * Wrapper class for holding a key pair.
 */
class KeyPair(private val publicKey: PublicKey, private val privateKey: PrivateKey) {

    // @return the original private key object
    val private: PrivateKey
        get() = privateKey

    // @return the original public key object
    val public: PublicKey
        get() = publicKey

    // @return Base64-encoded private key
    val privateBase64: String
        get() = Base64.getEncoder().encodeToString(privateKey.encoded)

    // @return Base64-encoded public key
    val publicBase64: String
        get() = Base64.getEncoder().encodeToString(publicKey.encoded)
}