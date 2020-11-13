package za.co.indrajala.fluid.crypto

import android.icu.util.Calendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import za.co.indrajala.fluid.attestation.Google
import za.co.indrajala.fluid.bit.toHex
import za.co.indrajala.fluid.crypto.java.summary
import za.co.indrajala.fluid.crypto.java.toDER
import za.co.indrajala.fluid.log
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.SignatureException
import java.security.cert.Certificate
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal
import kotlin.system.measureTimeMillis

class AndroidKeyStore {
    companion object {

        private const val ANDROID_KEYSTORE_TYPE = "AndroidKeyStore"
        private const val ANDROID_KEYSTORE_NAME = "AndroidKeyStore"

        private var ks: KeyStore? = null

        fun initialize(): Boolean {
            log.v_header("android keystore")

            if (ks != null) {
                log.v("keystore has already been initialized.")
                return true
            }

            try {
                log.v("getting reference to keystore instance...")
                val localKS: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_TYPE)

                log.v("loading keystore persistence from input stream...")
                localKS.load(null)

                ks = localKS

                log.v("${localKS.summary()}")

                return true
            } catch (kse: KeyStoreException) {
                log.e("get keystore instance and load from input stream", kse)
                return false
            }
        }

        fun validateCertChain(chain: List<X509Certificate>): CertChainValidationError {

            //val kd = KeyDescription.fromX509Cert(chainCert)

            val roots = chain.filter { it.issuerDN.name == it.subjectDN.name }
            if (roots.isEmpty())
                return CertChainValidationError.NoRoot
            if (roots.size > 1)
                return CertChainValidationError.MoreThanOneRoot
            val root = roots[0]

            val ordered = arrayListOf<X509Certificate>(root)
            val remainder = ArrayList(chain.filter { it != root })

            while (ordered.size < chain.size) {
                val child = remainder.firstOrNull { it.issuerDN == ordered.last().subjectDN }
                    ?: return CertChainValidationError.BrokenChain

                ordered.add(child)
                remainder.remove(child)
            }

            ordered.forEachIndexed { index, child ->

                val details = "$index: Issued By ${child.issuerDN.name}, Subject ${child.subjectDN.name}"

                fun log(text: String) =
                    log.v("$index $text $details")

                // date
                try {
                    child.checkValidity()
                }
                catch (expired: CertificateExpiredException) {
                    log("expired")
                    return CertChainValidationError.CertificateExpired
                } catch (notYetValid: CertificateNotYetValidException) {
                    log("not yet valid")
                    return CertChainValidationError.CertificateNotYetValid
                }

                val parent = if (index == 0)
                    child
                else
                    ordered[index - 1]

                try {
                    child.verify(parent.publicKey)
                } catch (signature: SignatureException) {
                    log("bad signature")
                    return CertChainValidationError.BadSignature
                } catch (e: Exception) {
                    log("unable to validate signature")
                    return CertChainValidationError.UnableToValidateSignature
                }

                log("valid")
            }

            return CertChainValidationError.None
        }

        fun getCertChainForKey(alias: String): List<Certificate> {
            val targetCert: Certificate = ks!!.getCertificate(alias)

            val certChain = ks!!.getCertificateChain(alias)
            log.v("attestation chain for fluid device root key contains ${certChain.size} certificates:");

            val indexOfDeviceRootKeyCert =  certChain.indexOfFirst { it.toDER() == targetCert.toDER() }
            log.v("fluid device root key is $indexOfDeviceRootKeyCert in the chain")

            log.v("checking against ${Google.ROOT_CERTS_DER.size} currently valid known google root certs...")
            val googleRoots = certChain
                .filter { rootCert -> Google.ROOT_CERTS_DER.count { it == rootCert.toDER() } > 0 }
            log.v("${googleRoots.size} matching google root cert(s):")
            googleRoots.forEach {
                log.v(it.toDER())
            }
            check(googleRoots.size == 1, { println("should have one and only one matching root") })
            val googleRootCert = googleRoots[0]!!
            val indexOfGoogleRootKeyCert =  certChain.indexOfFirst { it.toDER() == googleRootCert.toDER() }
            log.v("google root key is $indexOfGoogleRootKeyCert in the chain")

            return certChain.toList()
        }

        fun generateDeviceRootKey(
            alias: String,
            serialNumber: Long,
            serverChallenge: ByteArray,
            lifeTimeMinutes: Int,
            sizeInBits: Int
        ): Boolean {
            log.v_header("generate and attest device root key")

            val validFrom = Calendar.getInstance()

            val validTo = validFrom.clone() as Calendar
            validTo.add(Calendar.MINUTE, lifeTimeMinutes)

            // TODO distinguish between cert and key lifetimes

            val keyPurpose = KeyProperties.PURPOSE_VERIFY or
                    KeyProperties.PURPOSE_SIGN or
                    KeyProperties.PURPOSE_WRAP_KEY

            val keySpecBuilder: KeyGenParameterSpec.Builder = KeyGenParameterSpec
                .Builder(alias, keyPurpose)
                .setCertificateSubject(X500Principal("CN=${alias}"))
                .setCertificateSerialNumber(BigInteger.valueOf(serialNumber))
                .setDigests(KeyProperties.DIGEST_SHA512)
                // cert validity
                .setCertificateNotBefore(validFrom.time)
                .setCertificateNotAfter(validTo.time)
                .setKeySize(sizeInBits)
                // key validity
                .setKeyValidityStart(validFrom.time)
                .setKeyValidityEnd(validTo.time)

            keySpecBuilder.setAttestationChallenge(serverChallenge)
            log.d("using server challenge", serverChallenge.toHex())

            //.setIsStrongBoxBacked(true) => android.security.keystore.StrongBoxUnavailableException: Failed to generate key pair

            when (keyPurpose) {

                KeyProperties.PURPOSE_VERIFY,
                KeyProperties.PURPOSE_SIGN -> {
                    keySpecBuilder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)

                    // SIGNATURE_PADDING_RSA_PSS
                    // SIGNATURE_PADDING_RSA_PKCS1
                }

                KeyProperties.PURPOSE_ENCRYPT,
                KeyProperties.PURPOSE_DECRYPT -> {
                    keySpecBuilder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)

                    // ENCRYPTION_PADDING_NONE
                    // ENCRYPTION_PADDING_PKCS7
                    // ENCRYPTION_PADDING_RSA_PKCS1
                    // ENCRYPTION_PADDING_RSA_OAEP
                }

                KeyProperties.PURPOSE_WRAP_KEY -> Unit

                else -> Unit
            }

            val keyGenParamSpec = keySpecBuilder.build()

            // log.v("KeySpec.isStrongBoxBacked", keySpec.isStrongBoxBacked)

            val keyGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE_NAME)

            keyGenerator.initialize(keyGenParamSpec)

            val keyGenTime = measureTimeMillis { keyGenerator.generateKeyPair() }

            log.v("generated $sizeInBits bit asymmetric RSA key in $keyGenTime ms")

            return true
        }
    }
}


