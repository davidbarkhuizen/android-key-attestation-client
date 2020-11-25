package za.co.indrajala.fluid.crypto

import android.icu.util.Calendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import za.co.indrajala.fluid.attestation.Google
import za.co.indrajala.fluid.attestation.enums.Algorithm
import za.co.indrajala.fluid.attestation.enums.Digest
import za.co.indrajala.fluid.attestation.enums.Padding
import za.co.indrajala.fluid.attestation.enums.Purpose
import za.co.indrajala.fluid.bit.hexToUBytes
import za.co.indrajala.fluid.crypto.java.summary
import za.co.indrajala.fluid.crypto.java.toDER
import za.co.indrajala.fluid.log
import za.co.indrajala.fluid.model.AsymmetricKeyParameters
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
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

        fun generateHwAttestedKey(
                alias: String,
                keyParams: AsymmetricKeyParameters
        ): Boolean {
            log.v_header("generate and attest device root key")

            // TODO distinguish between cert and key lifetimes

            // temporal validity
            //
            val validFrom = Calendar.getInstance()
            val validTo = validFrom.clone() as Calendar
            validTo.add(Calendar.MINUTE, keyParams.lifetimeMinutes)

            // TODO move mappings to standalone location

            val purpose = when (keyParams.purpose) {
                Purpose.Decrypt -> KeyProperties.PURPOSE_DECRYPT
                Purpose.Encrypt -> KeyProperties.PURPOSE_ENCRYPT
                Purpose.Sign -> KeyProperties.PURPOSE_SIGN
                Purpose.Verify -> KeyProperties.PURPOSE_VERIFY
                Purpose.WrapKey -> KeyProperties.PURPOSE_WRAP_KEY
                Purpose.DeriveKey -> throw UnsupportedOperationException("(Key)Purpose.DeriveKey")
            }

            val digest = when (keyParams.digest) {
                Digest.NONE -> KeyProperties.DIGEST_NONE
                Digest.MD5 -> KeyProperties.DIGEST_MD5
                Digest.SHA1 -> KeyProperties.DIGEST_SHA1
                Digest.SHA_2_224 -> KeyProperties.DIGEST_SHA224
                Digest.SHA_2_256 -> KeyProperties.DIGEST_SHA256
                Digest.SHA_2_384 -> KeyProperties.DIGEST_SHA384
                Digest.SHA_2_512 -> KeyProperties.DIGEST_SHA512
            }

            val keySpecBuilder: KeyGenParameterSpec.Builder = KeyGenParameterSpec
                .Builder(alias, purpose)
                .setCertificateSubject(X500Principal("CN=${alias}"))
                .setCertificateSerialNumber(BigInteger.valueOf(keyParams.serialNumber.toLong()))
                .setKeySize(keyParams.sizeInBits)
                .setDigests(digest)
                .setKeyValidityStart(validFrom.time)
                .setKeyValidityEnd(validTo.time)
                .setCertificateNotBefore(validFrom.time)
                .setCertificateNotAfter(validTo.time)

            // challenge: TODO mix in data
            //
            keySpecBuilder.setAttestationChallenge(keyParams.challenge.hexToUBytes().toByteArray())
            log.d("using server challenge", keyParams.challenge)

            when (keyParams.purpose) {
                Purpose.Decrypt, Purpose.Encrypt -> {
                    val padding = when (keyParams.padding) {
                        Padding.NONE -> KeyProperties.ENCRYPTION_PADDING_NONE
                        Padding.PKCS7 -> KeyProperties.ENCRYPTION_PADDING_PKCS7
                        Padding.RSA_OAEP -> KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
                        Padding.RSA_PKCS1_1_5_ENCRYPT -> KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1

                        Padding.RSA_PSS,
                        Padding.RSA_PKCS1_1_5_SIGN ->
                            throw UnsupportedOperationException("RSA_PSS, RSA_PKCS1_1_5_SIGN paddings not supported for enc/dev")
                    }

                    keySpecBuilder.setEncryptionPaddings(padding)
                }
                Purpose.Sign, Purpose.Verify -> {
                    val padding = when (keyParams.padding) {
                        Padding.RSA_PKCS1_1_5_SIGN -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
                        Padding.RSA_PSS -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
                        Padding.NONE, Padding.RSA_PKCS1_1_5_ENCRYPT, Padding.PKCS7, Padding.RSA_OAEP->
                            throw UnsupportedOperationException("NONE, RSA_PKCS1_1_5_ENCRYPT, PKCS7 paddings not supported for sign/verify")
                    }

                    keySpecBuilder.setSignaturePaddings(padding)
                }
                else -> Unit
            }

            //  NIST P-256 (aka secp256r1 aka prime256v1)
            //  secp256r1
            //
            when (keyParams.algorithm) {
                Algorithm.EC ->
                    keySpecBuilder.setAlgorithmParameterSpec(
                        ECGenParameterSpec(keyParams.ecCurve)
                    )
                Algorithm.RSA ->
                    keySpecBuilder.setAlgorithmParameterSpec(
                        RSAKeyGenParameterSpec(
                            keyParams.sizeInBits,
                            BigInteger.valueOf(keyParams.rsaExponent.toLong())
                        )
                    )
            }

            if (keyParams.requireHSM) {
                keySpecBuilder.setIsStrongBoxBacked(true)
            }

            val keyGenParamSpec = keySpecBuilder.build()

            val algorithm = when (keyParams.algorithm) {
                Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC
                Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA
                else -> throw UnsupportedOperationException("algorithm not supported for asymmetric key generation ${keyParams.algorithm}")
            }

            val keyGenerator: KeyPairGenerator =
                KeyPairGenerator.getInstance(algorithm, ANDROID_KEYSTORE_NAME)

            // TODO initialize with entropy from the server ?
            keyGenerator.initialize(keyGenParamSpec, SecureRandom())


            val keyGenTime = measureTimeMillis { val generated = keyGenerator.generateKeyPair() }
            log.v("generated ${keyParams.sizeInBits} bit asymmetric key in $keyGenTime ms")

            return true
        }
    }
}


