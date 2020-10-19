package za.co.indrajala.fluid

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import za.co.indrajala.fluid.crypto.KeyPurpose
import za.co.indrajala.fluid.util.log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore

class Fluid {

    companion object {

        private const val ROOT_KEY_ALIAS = "fluid.root"
        private const val KEY_STORE_NAME = "fluid"

        private val keystoreSecret: CharArray = "password".toCharArray()
    }

    private fun deviceFingerprint() {
        val apiLevel = android.os.Build.VERSION.SDK_INT

        log.v("device fingerprint")
        log.v("android API level", apiLevel)
    }

    fun init() {
        log.v("Fluid Authentication & Authorization from Indrajala")

        deviceFingerprint()

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")

        log.v("KeyStore")
        log.v("type", ks.type)
        log.v("provider", ks.provider.name)
        // JKS java key store (Oracle JDK)
        // BKS bouncy-castle key store

        ks.load(null)

        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
        )

        val keySpec = KeyGenParameterSpec.Builder(ROOT_KEY_ALIAS, KeyPurpose.Integrity.ordinal)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setKeySize(4096)
            .build()

        log.v("KeySpec.isStrongBoxBacked", keySpec.isStrongBoxBacked)

        keyGenerator.initialize(keySpec)

        val keyPair = keyGenerator.generateKeyPair()

        val entry = ks.getEntry(ROOT_KEY_ALIAS, null)
        val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
        val publicKey = ks.getCertificate(ROOT_KEY_ALIAS).publicKey


        val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

        val isInsideSecureHardware: Boolean = keyInfo.isInsideSecureHardware
        log.v("PvtKey.KeyInfo.isInsideSecureHardware", isInsideSecureHardware)
    }
}