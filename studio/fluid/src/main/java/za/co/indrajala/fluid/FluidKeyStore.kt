package za.co.indrajala.fluid

import android.icu.util.Calendar
import android.icu.util.GregorianCalendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.google.gson.Gson
import za.co.indrajala.fluid.asn1.ASN1
import za.co.indrajala.fluid.crypto.*
import za.co.indrajala.fluid.http.HTTP
import za.co.indrajala.fluid.model.PublicKeyCert
import za.co.indrajala.fluid.util.log
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.cert.Certificate
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

//            val entry = ks!!.getEntry(alias, null)
//
//            val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
//            val keyFactory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEY_STORE_NAME)
//
//            val pvtKeyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
//            log.v(pvtKeyInfo.summary())

            val cert: Certificate = ks!!.getCertificate(alias)
            log.v(".PEM: B64")
            log.v(cert.toPEM())
            log.v(".CER: ASN.1 DER")
            log.v(cert.toDER())

            log.v("BC ASN.1 parse:")
            log.v(ASN1.describe(cert.encoded))

            // ------------------------------

            val certChain = ks!!.getCertificateChain(alias)

            log.v("attestation chain - ${certChain.size} links");
            certChain.forEachIndexed { i, it ->
                log.v_header("CHAIN KEY $i")
                log.v(it.toDER())
                log.v(it.toPEM())
            }

            HTTP.post(
                "http://192.168.8.103:8777/device/register",
                Gson().toJson(PublicKeyCert(cert.toDER(), certChain.map { it.toDER() }))
            )
        }

        fun generateDeviceRootKey(
            serverNonce: ByteArray
        ) {

            log.v_header("key generation")

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

            val keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE_NAME
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

            keyGenerator.initialize(keySpec)

            keyGenerator.generateKeyPair()
        }
    }
}

