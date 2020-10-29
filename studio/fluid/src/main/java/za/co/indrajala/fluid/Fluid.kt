package za.co.indrajala.fluid

import za.co.indrajala.fluid.crypto.*
import za.co.indrajala.fluid.util.log

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
        FluidKeyStore.attestDeviceRootKey()
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

        val keystoreInitialized = FluidKeyStore.initialize()

        val serverChallenge = RNG.bytes(8)

        val generatedDeviceRootKey = FluidKeyStore.generateDeviceRootKey(
            serialNumber = 0,
            serverNonce = serverChallenge,
            lifeTimeMinutes = 60*24,
            sizeInBits = 2048
        )

        return this
    }
}