package za.co.indrajala.fluid.crypto

import android.icu.util.Calendar
import android.icu.util.GregorianCalendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import za.co.indrajala.fluid.attestation.Google
import za.co.indrajala.fluid.crypto.java.X509
import za.co.indrajala.fluid.attestation.KeyDescription
import za.co.indrajala.fluid.bit.toHex
import za.co.indrajala.fluid.crypto.java.summary
import za.co.indrajala.fluid.crypto.java.toDER
import za.co.indrajala.fluid.crypto.java.toPEM
import za.co.indrajala.fluid.log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import javax.security.auth.x500.X500Principal

class AndroidKeyStore {
    companion object {

        private const val ANDROID_KEYSTORE_TYPE = "AndroidKeyStore"
        private const val ANDROID_KEYSTORE_NAME = "AndroidKeyStore"

        const val DEVICE_ROOT_KEYSTORE_ALIAS = "fluid.device.key"

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

        fun attestFluidDeviceRootKey(
        ) {
            log.v_header("device root key attestation")

            val targetCert: Certificate = ks!!.getCertificate(DEVICE_ROOT_KEYSTORE_ALIAS)

            log.v(".DER: ASN.1")
            log.v(targetCert.toDER())

            log.v(".PEM: B64")
            log.v(targetCert.toPEM())

//            log.v("BC ASN.1 parse:")
//            log.v(ASN1.describe(cert.encoded))

            // ------------------------------

            val certChain = ks!!.getCertificateChain(DEVICE_ROOT_KEYSTORE_ALIAS)

            log.v("attestation chain for fluid device root key contains ${certChain.size} certificates:");
            certChain.forEachIndexed { i, it ->
                val der = it.toDER()
                val pem = it.toPEM()

                val x509 = X509.fromPEM(pem)
                val subjectName = x509.subjectDN.name

                log.v("$i (len ${der.length / 2}) $subjectName $der")
            }

            // ------------------------------

            val indexOfDeviceRootKeyCert =  certChain.indexOfFirst { it.toDER() == targetCert.toDER() }
            log.v("fluid device root key is $indexOfDeviceRootKeyCert in the chain")
            // ------------------------------

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

            certChain
                .map { X509.fromPEM(it.toPEM()) }
                .forEachIndexed { index, chainCert ->
                    log.v_header("CERT $index")

                    val kd = KeyDescription.fromX509Cert(chainCert)

                    val summary =
                        if (kd == null)
                            chainCert.summary()
                        else
                            listOf(
                                Pair("X.509 CERT -------------------------", ""),
                                *chainCert.summary().toTypedArray(),
                                Pair("Key Attestation X.509 Extension ----", ""),
                                *kd.summary().toTypedArray()
                            )

                    summary
                        .filter { it.second != null}
                        .forEach {
                            log.v(it.first.padEnd(40) + it.second)
                        }
                }

//            HTTP.post(
//                "http://192.168.8.103:8777/device/register",
//                Gson().toJson(PublicKeyCert(cert.toDER(), certChain.map { it.toDER() }))
//            )
        }

        fun generateDeviceRootKey(
            serialNumber: Long,
            serverNonce: ByteArray,
            lifeTimeMinutes: Int,
            sizeInBits: Int
        ): Boolean {
            log.v_header("DEVICE ROOT KEY")

            val validFrom = GregorianCalendar()
            val validTo = validFrom.clone() as GregorianCalendar
            validTo.add(Calendar.MINUTE, lifeTimeMinutes)

            val params = AsymKeyParams(
                subjectCommonName = DEVICE_ROOT_KEYSTORE_ALIAS,
                certSN = serialNumber,
                keySizeBits = sizeInBits,
                purpose = KeyPurpose.Integrity,
                digest = KeyProperties.DIGEST_SHA512,
                signaturePadding = KeyProperties.SIGNATURE_PADDING_RSA_PSS,
                validFrom = validFrom,
                validTo = validTo
            )

            val keySpecBuilder = KeyGenParameterSpec
                .Builder(DEVICE_ROOT_KEYSTORE_ALIAS, params.purpose.purpose)
                .setCertificateSubject(X500Principal("CN=${params.subjectCommonName}"))
                .setCertificateSerialNumber(params.certSN)
                .setDigests(params.digest)
                .setCertificateNotBefore(validFrom.time)
                .setCertificateNotAfter(validTo.time)
                .setKeySize(params.keySizeBits)

            keySpecBuilder.setAttestationChallenge(serverNonce)
            log.d("using server challenge / nonce", serverNonce.toHex())

            //.setIsStrongBoxBacked(true) => android.security.keystore.StrongBoxUnavailableException: Failed to generate key pair

            if (params.purpose == KeyPurpose.Integrity) {
                keySpecBuilder
                    .setSignaturePaddings(params.signaturePadding)
            } else {
                keySpecBuilder
                    .setEncryptionPaddings(params.encryptionPadding)
            }

            val keyGenParamSpec = keySpecBuilder.build()

            // log.v("KeySpec.isStrongBoxBacked", keySpec.isStrongBoxBacked)

            val keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE_NAME
            )

            keyGenerator.initialize(keyGenParamSpec)
            keyGenerator.generateKeyPair()

            log.v("generated S/N $serialNumber, $sizeInBits bits, valid for $lifeTimeMinutes minutes")

            return true
        }
    }
}


