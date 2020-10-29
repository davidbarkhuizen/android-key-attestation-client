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

    private fun fingerprintDevice() {
        log.v_header("device fingerprint")

        val apiLevel = android.os.Build.VERSION.SDK_INT
        log.v("Android API level", apiLevel)
    }

    fun test() {
        FluidKeyStore.attestPublicKey(FluidKeyStore.DEVICE_ROOT_KEY_ALIAS)
    }

    fun init(): Fluid {
        log.v("Fluid Integrity & Confidentiality - (C) 2020, Indrajala (Pty) Ltd")

        if (initialized) {
            log.v("the Fluid module has already initialized!")
            return this
        }

        fingerprintDevice()

        val initialized = FluidKeyStore.initialize()

        val serverChallenge = RNG.bytes(8)
        FluidKeyStore.generateDeviceRootKey(serverChallenge)

        return this
    }
}