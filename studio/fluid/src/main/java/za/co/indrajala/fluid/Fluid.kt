package za.co.indrajala.fluid

import za.co.indrajala.fluid.crypto.*

class Fluid {

    companion object {
        private const val ROOT_KEY_ALIAS = "fluid.root"
        private const val KEY_STORE_NAME = "fluid"

        //private val keystoreSecret: CharArray = "password".toCharArray()
    }

    private var initialized = false

    private fun fingerprintDevice(): DeviceFingerprint {
        return DeviceFingerprint(
            android.os.Build.VERSION.SDK_INT
        )
    }

    fun test() {
        AndroidKeyStore.attestFluidDeviceRootKey()
    }

    fun init(): Fluid {
        log.v_header("Fluid Integrity & Confidentiality - (C) 2020, Indrajala (Pty) Ltd", 80, '=')

        if (initialized) {
            log.v("the Fluid module has already initialized!")
            return this
        }

        log.v_header("device fingerprint")
        val deviceFingerprint = fingerprintDevice()
        log.v(deviceFingerprint.toString())

        check(AndroidKeyStore.initialize())

        val serverChallenge = RNG.bytes(8)

        check(AndroidKeyStore.generateDeviceRootKey(
            serialNumber = 0,
            serverNonce = serverChallenge,
            lifeTimeMinutes = 60*24,
            sizeInBits = 2048
        ))

        AndroidKeyStore.attestFluidDeviceRootKey()

        return this
    }
}