package za.co.indrajala.fluid

import android.icu.util.Calendar
import android.icu.util.GregorianCalendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import za.co.indrajala.fluid.asn1.ASN1
import za.co.indrajala.fluid.crypto.*
import za.co.indrajala.fluid.util.log
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import javax.security.auth.x500.X500Principal

class FluidKeyStore {
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

        fun attestDeviceRootKey(
        ) {
            log.v_header("device root key attestation")

            val cert: Certificate = ks!!.getCertificate(DEVICE_ROOT_KEYSTORE_ALIAS)

            log.v(".DER: ASN.1")
            log.v(cert.toDER())

            log.v(".PEM: B64")
            log.v(cert.toPEM())

//            log.v("BC ASN.1 parse:")
//            log.v(ASN1.describe(cert.encoded))

            // ------------------------------

            val certChain = ks!!.getCertificateChain(DEVICE_ROOT_KEYSTORE_ALIAS)

            log.v("attestation chain for fluid device root key contains ${certChain.size} certificates:");
            certChain.forEachIndexed { i, it ->
                val der = it.toDER()
                log.v("$i (len ${der.length / 2}) $der")
            }

            // ------------------------------

            log.v("checking against ${GoogleHardwareAttestation.rootCertsDER.size} currently valid known google root certs...")

            val googleRoots = certChain
                .filter { rootCert -> GoogleHardwareAttestation.rootCertsDER.count { it == rootCert.toDER() } > 0 }

            log.v("${googleRoots.size} matching google root cert(s):")
            googleRoots.forEach {
                log.v(it.toDER())
            }

            check(googleRoots.size == 1, { println("should have one and only one matching root") })

            val certFactory = CertificateFactory.getInstance("X.509");

            val attestationCerts = certChain.map {
                certFactory.generateCertificate(
                    (ByteArrayInputStream(certChain[0].toPEM().toByteArray()))
                ) as X509Certificate
            }.filter {
                val attestation = it.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                (attestation != null)
            }

            log.v("${attestationCerts.size} certs with attestation data in chain")


//                val policyInformation = policies.policyInformation.forEach {
//                    val policyQualifiers =  it.policyQualifiers.getObjectAt  (0) as ASN1Sequence
//                    System.out.println(policyQualifiers.getObjectAt(1)); // aaa.bbb
//                }

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
        ) {
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
                .setAttestationChallenge(serverNonce)

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
        }
    }
}


