package za.co.indrajala.fluid

import android.R.attr.key
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore


class Fluid {

    companion object {

        val ENC_DEC = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        val SIGN_VERIFY = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY

        private const val ANDROID_LOG_TAG = "fluid.log"
        private const val ROOT_KEY_ALIAS = "fluid.root"
        private const val KEY_STORE_NAME = "fluid"

        private val keystoreSecret: CharArray = "password".toCharArray()

        private fun log(s: String) {
            Log.v(ANDROID_LOG_TAG, s)
        }

        private fun log(label: String, text: String) {
            log("$label: $text")
        }

        private fun log(label: String, number: Int) {
            log("$label: $number")
        }

        private fun log(label: String, predicate: Boolean) {
            log("$label: $predicate")
        }
    }

    fun fingerprintDevice() {
        val apiLevel = android.os.Build.VERSION.SDK_INT

        log("device fingerprint")
        log("android API level", apiLevel)
    }

    fun init() {
        log("Fluid Authentication & Authorization from Indrajala")

        fingerprintDevice()

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")

        log("KeyStore")
        log("type", ks.type)
        log("provider", ks.provider.name)
        // JKS java key store (Oracle JDK)
        // BKS bouncy-castle key store

        ks.load(null)

        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
        )

        val keySpec = KeyGenParameterSpec.Builder(ROOT_KEY_ALIAS, SIGN_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setKeySize(4096)
            .build()

        log("KeySpec.isStrongBoxBacked", keySpec.isStrongBoxBacked)

        keyGenerator.initialize(keySpec)

        val keyPair = keyGenerator.generateKeyPair()

        val entry = ks.getEntry(ROOT_KEY_ALIAS, null)
        val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
        val publicKey = ks.getCertificate(ROOT_KEY_ALIAS).publicKey


        val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

        val isInsideSecureHardware: Boolean = keyInfo.isInsideSecureHardware
        log("PvtKey.KeyInfo.isInsideSecureHardware", isInsideSecureHardware)
    }
}