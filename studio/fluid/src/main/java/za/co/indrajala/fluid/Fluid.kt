package za.co.indrajala.fluid

import android.content.Context
import com.google.gson.Gson
import za.co.indrajala.fluid.bit.hexToUBytes
import za.co.indrajala.fluid.crypto.*
import za.co.indrajala.fluid.crypto.java.toDER
import za.co.indrajala.fluid.http.HTTP
import za.co.indrajala.fluid.model.device.*

class Fluid {

    companion object {
        private const val RootKeyAlias = "fluid.root"
    }

    private var initialized = false

    // device registration

    private fun indicateIntentToRegisterDevice() {
        HTTP.post(
            "/device/register/intent",
            DevRegInitRq(),
            ::handleDevRegIntentRsp
        )
    }

    private fun handleDevRegIntentRsp(json: String?) {
        val permission = Gson()
            .fromJson(json!!, DevRegInitRsp::class.java)

        // TODO check that we do indeed have permission

        // generate device root key using received params

        check(AndroidKeyStore.generateDeviceRootKey(
            serialNumber = permission.keySN,
            serverChallenge = permission.keyAttestationChallenge.hexToUBytes().toByteArray(),
            lifeTimeMinutes = permission.keyLifeTimeMinutes,
            sizeInBits = permission.keySizeBits
        ))

        val chain = AndroidKeyStore.getCertChainForKey(RootKeyAlias)

        HTTP.post(
            "/device/register/execute",
            DevRegCompletionRq(
                permission.registrationID,
                chain.map { it.toDER() },
            ),
            ::handleDevRegResult
        )
    }

    private fun handleDevRegResult(json: String?) {
        val regResult = Gson()
            .fromJson(json!!, DevRegCompletionRsp::class.java)

        log.v(
            if (regResult.succeeded)
                "device registered"
            else
                "device registration failed"
        )
    }

    fun registerDevice() {
        indicateIntentToRegisterDevice()
    }

    fun init(context: Context): Fluid {
        log.v_header("Fluid Integrity & Confidentiality - (C) 2020, Indrajala (Pty) Ltd", 80, '=')

        if (initialized) {
            log.v("the Fluid module has already initialized!")
            return this
        }

        log.v_header("device fingerprint")
        val deviceFingerprint = DeviceFingerprint.print(context)
        log.v(deviceFingerprint.toString())

        check(AndroidKeyStore.initialize())

        return this
    }
}