package za.co.indrajala.fluid

import android.icu.util.Calendar
import android.icu.util.GregorianCalendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x509.CertificatePolicies
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.PolicyInformation
import org.bouncycastle.x509.extension.X509ExtensionUtil
import za.co.indrajala.fluid.asn1.ASN1
import za.co.indrajala.fluid.crypto.*
import za.co.indrajala.fluid.util.log
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

class FluidKeyStore {
    companion object {

        private const val ANDROID_KEY_STORE_TYPE = "AndroidKeyStore"
        private const val ANDROID_KEY_STORE_NAME = "AndroidKeyStore"

        const val DEVICE_ROOT_KEY_ALIAS = "fluid.device.key"

        private var ks: KeyStore? = null

        fun initialize(): Boolean {
            log.v_header("initializing Android Keystore")

            if (ks != null) {
                log.v("keystore has already been initialized.")
                return true
            }

            try {
                log.v("getting reference to keystore instance...")
                val localKS: KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE_TYPE)

                log.v("loading keystore persistence from input stream...")
                localKS.load(null)

                ks = localKS

                log.v("keystore initialized: ${localKS.summary()}")

                return true
            } catch (kse: KeyStoreException) {
                log.e("get keystore instance and load from input stream", kse)
                return false
            }
        }

        fun attestPublicKey(
            alias: String
        ) {
            log.v_header("attesting public key with alias $alias")

            val cert: Certificate = ks!!.getCertificate(alias)
            log.v(".PEM: B64")
            log.v(cert.toPEM())
            log.v(".CER: ASN.1 DER")
            log.v(cert.toDER())

            log.v("BC ASN.1 parse:")
            log.v(ASN1.describe(cert.encoded))

            // ------------------------------

            val certChain = ks!!.getCertificateChain(alias)

            log.v("attestation chain contains ${certChain.size} certificates");
            certChain.forEachIndexed { i, it ->
                val der = it.toDER()
                log.v("$i (len ${der.length / 2}) $der")
            }

            // ------------------------------

            val googleRoots = certChain
                .filter { rootCert-> GoogleHardwareAttestation.rootCertsDER.count { it == rootCert.toDER() } > 0 }

            log.v("${googleRoots.size} matching google hardware attestation root cert(s)")
            googleRoots.forEach {
                log.v(it.toDER())
            }

            check(googleRoots.size == 1, { println("should have one and only one matching root") })

            val certFactory = CertificateFactory.getInstance("X.509");
            val rootCert = certFactory.generateCertificate(ByteArrayInputStream(certChain[0].toPEM().toByteArray())) as X509Certificate

            val attestation = rootCert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
            if (attestation != null) {
                log.v("GOTCHA")
                attestation.

                val policyInformation = policies.policyInformation.forEach {
                    val policyQualifiers =  it.policyQualifiers.getObjectAt  (0) as ASN1Sequence
                    System.out.println(policyQualifiers.getObjectAt(1)); // aaa.bbb
                }
            }

//            HTTP.post(
//                "http://192.168.8.103:8777/device/register",
//                Gson().toJson(PublicKeyCert(cert.toDER(), certChain.map { it.toDER() }))
//            )
        }

        fun generateDeviceRootKey(
            serverNonce: ByteArray
        ) {
            log.v("generating key...")

            val validFrom = GregorianCalendar()

            val minutes = 30

            val validTo = validFrom.clone() as GregorianCalendar
            validTo.add(Calendar.MINUTE, minutes)

            val params = AsymKeyParams(
                2048,
                KeyPurpose.Integrity,
                DEVICE_ROOT_KEY_ALIAS,
                BigInteger.valueOf(33),
                KeyProperties.DIGEST_SHA512,
                KeyProperties.SIGNATURE_PADDING_RSA_PSS,
                validFrom,
                validTo
            )

            val keySpec = KeyGenParameterSpec
                .Builder(DEVICE_ROOT_KEY_ALIAS, params.usages.purpose)
                .setCertificateSubject(X500Principal("CN=${params.subjectCommonName}"))
                .setCertificateSerialNumber(params.certSN)
                .setDigests(params.permittedDigest)
                .setSignaturePaddings(params.signaturePadding)
                .setCertificateNotBefore(validFrom.time)
                .setCertificateNotAfter(validTo.time)
                .setKeySize(params.keySizeBits)
                //.setIsStrongBoxBacked(true) => android.security.keystore.StrongBoxUnavailableException: Failed to generate key pair
                .setAttestationChallenge(serverNonce)
                .build()

            // log.v("KeySpec.isStrongBoxBacked", keySpec.isStrongBoxBacked)

            val keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE_NAME
            )

            keyGenerator.initialize(keySpec)
            keyGenerator.generateKeyPair()

            log.v("generated.")
        }
    }
}

