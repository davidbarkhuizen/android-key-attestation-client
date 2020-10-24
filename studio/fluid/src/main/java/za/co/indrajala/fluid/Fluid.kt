package za.co.indrajala.fluid

import android.icu.util.Calendar
import android.icu.util.GregorianCalendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.google.gson.Gson
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
import kotlin.system.measureTimeMillis

class Fluid {

    companion object {

        private const val ANDROID_KEY_STORE_TYPE = "AndroidKeyStore"
        private const val ANDROID_KEY_STORE_NAME = "AndroidKeyStore"

        private const val ROOT_KEY_ALIAS = "fluid.root"
        private const val KEY_STORE_NAME = "fluid"

        //private val keystoreSecret: CharArray = "password".toCharArray()
    }

    private var initialized = false

    private var ks: KeyStore? = null
    private fun initializeKeystore(): Boolean {

        log.v_header("keystore initialization")

        if (ks != null) {
            log.v("keystore has already been initialized.")
            return true
        }

        try {
            log.v("getting reference to keystore instance...")
            ks = KeyStore.getInstance(ANDROID_KEY_STORE_TYPE)

            log.v("loading keystore persistence from input stream...")
            ks!!.load(null)
        } catch (kse: KeyStoreException) {
            log.e("get keystore instance and load from input stream", kse)
            return false
        }

        log.v("keystore initialized:")
        log.v(ks!!.describe())
        return true
    }


    private fun fingerprintDevice() {
        log.v_header("device fingerprint")

        val apiLevel = android.os.Build.VERSION.SDK_INT
        log.v("Android API level", apiLevel)
    }

    private fun exportKey(alias: String) {

        log.v_header("key export")

        log.v("exporting rsa public cert of key with alias $alias")

        val entry = ks!!.getEntry(alias, null)

        val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
        val keyFactory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEY_STORE_NAME)

        val pvtKeyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
        log.v(pvtKeyInfo.describe())

        val cert: Certificate = ks!!.getCertificate(ROOT_KEY_ALIAS)
        log.v(".PEM: B64")
        log.v(cert.toPEM())
        log.v(".CER: ASN.1 DER")
        log.v(cert.toDER())

        log.v("BC ASN.1 parse:")
        log.v(ASN1.describe(cert.encoded))

        // ------------------------------

        val certChain = ks!!.getCertificateChain(ROOT_KEY_ALIAS)

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

    private fun generateDeviceRootKey(
        serverNonce: ByteArray
    ) {

        log.v_header("key generation")

        val alias = ROOT_KEY_ALIAS

        val keySize = 1024
        val usage = KeyPurpose.Integrity.ordinal

        val certSubjectCN = alias
        val certSN = BigInteger.valueOf(1)

        val digest = KeyProperties.DIGEST_SHA512
        val sigPadding = KeyProperties.SIGNATURE_PADDING_RSA_PSS

        val validFrom = GregorianCalendar()

        val minutes = 30

        val validTo = validFrom.clone() as GregorianCalendar
        validTo.add(Calendar.MINUTE, minutes)

        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE_NAME
        )

        val keySpec = KeyGenParameterSpec
            .Builder(alias, usage)
            .setCertificateSubject(X500Principal("CN=$certSubjectCN"))
            .setCertificateSerialNumber(certSN)
            .setDigests(digest)
            .setSignaturePaddings(sigPadding)
            .setCertificateNotBefore(validFrom.time)
            .setCertificateNotAfter(validTo.time)
            .setKeySize(keySize) // 4096 => not supported by low power key operation suite
            //.setIsStrongBoxBacked(true) => android.security.keystore.StrongBoxUnavailableException: Failed to generate key pair
            .setAttestationChallenge(serverNonce)
            .build()

        // log.v("KeySpec.isStrongBoxBacked", keySpec.isStrongBoxBacked)

        keyGenerator.initialize(keySpec)

        keyGenerator.generateKeyPair()

//        var sum: Long = 0
//        val count = 1
//        for (i in 1..count) {
//            val keyGenDurationMS = measureTimeMillis {
//                val keyPair = keyGenerator.generateKeyPair()
//            }
//            sum += keyGenDurationMS
//            log.v("$i generation of $keySize bit RSA keypair took $keyGenDurationMS ms")
//        }
//
//        var avg = sum / count
//        log.v("avg over $count $avg ms")

        // retrieve from KeyStore as if we didn't already have a reference
    }

    fun test() {
        exportKey(ROOT_KEY_ALIAS);
    }

    fun init(): Fluid {
        log.v("Fluid Integrity & Confidentiality - (C) 2020, Indrajala (Pty) Ltd")

        if (initialized) {
            log.v("the Fluid module has already initialized!")
            return this
        }

        fingerprintDevice()

        val initialized = initializeKeystore()

        val serverChallenge = RNG.bytes(8)
        generateDeviceRootKey(serverChallenge)

        return this
    }
}