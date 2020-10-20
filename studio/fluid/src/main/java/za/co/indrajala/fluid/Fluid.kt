package za.co.indrajala.fluid

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import za.co.indrajala.fluid.crypto.KeyPurpose
import za.co.indrajala.fluid.crypto.describe
import za.co.indrajala.fluid.util.log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import kotlin.system.measureTimeMillis

class Fluid {

    companion object {

        private const val ANDROID_KEY_STORE_NAME = "AndroidKeyStore"

        private const val ROOT_KEY_ALIAS = "fluid.root"
        private const val KEY_STORE_NAME = "fluid"

        private val keystoreSecret: CharArray = "password".toCharArray()
    }

    private var initialized = false
    private val ks: KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME)

    private fun fingerprintDevice() {
        val apiLevel = android.os.Build.VERSION.SDK_INT

        log.v("device fingerprint")
        log.v("Android API level", apiLevel)
    }

    private fun initializeKeystore() {

        log.v("KeyStore", "Type ${ks.type}, Provider ${ks.provider.name}")

        // providers
        // JKS java key store (Oracle JDK)
        // BKS bouncy-castle key store

        ks.load(null)
    }

    private fun generateDeviceRootKey() {

        log.v("generating asymmetric RSA key...")

        val alias = ROOT_KEY_ALIAS
        val keySize = 1024
        val usage = KeyPurpose.Integrity.ordinal
        val digest = KeyProperties.DIGEST_SHA512
        val sigPadding = KeyProperties.SIGNATURE_PADDING_RSA_PSS

        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE_NAME
        )

        val keySpec = KeyGenParameterSpec
            .Builder(alias, usage)
            .setDigests(digest)
            .setSignaturePaddings(sigPadding)
            .setKeySize(keySize) // 4096 => not supported by low power key operation suite
            //.setIsStrongBoxBacked(true) => android.security.keystore.StrongBoxUnavailableException: Failed to generate key pair
            .build()

        // log.v("KeySpec.isStrongBoxBacked", keySpec.isStrongBoxBacked)

        keyGenerator.initialize(keySpec)

        var sum: Long = 0
        val count = 1
        for (i in 1..count) {
            val keyGenDurationMS = measureTimeMillis {
                val keyPair = keyGenerator.generateKeyPair()
            }
            sum += keyGenDurationMS
            log.v("$i generation of $keySize bit RSA keypair took $keyGenDurationMS ms")
        }

        var avg = sum / count
        log.v("avg over $count $avg ms")

        // retrieve from KeyStore as if we didn't already have a reference

        val entry = ks.getEntry(ROOT_KEY_ALIAS, null)
        val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
        val publicKey = ks.getCertificate(ROOT_KEY_ALIAS).publicKey

        val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEY_STORE_NAME)
        val pvtKeyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

        log.v(pvtKeyInfo.describe())

        val isInsideSecureHardware: Boolean = pvtKeyInfo.isInsideSecureHardware
        log.v("PvtKey.KeyInfo.isInsideSecureHardware", isInsideSecureHardware)
    }

    fun init(): Fluid {
        log.v("Fluid Integrity & Confidentiality - (C) 2020, Indrajala (Pty) Ltd")

        if (initialized) {
            log.v("already initialized")
            return this
        }

        log.v("initializing...")

        fingerprintDevice()
        initializeKeystore()

        generateDeviceRootKey()

        return this
    }
}