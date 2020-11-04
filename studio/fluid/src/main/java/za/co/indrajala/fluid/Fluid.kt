package za.co.indrajala.fluid

import android.content.Context
import com.google.gson.Gson
import za.co.indrajala.fluid.bit.hexToUBytes
import za.co.indrajala.fluid.crypto.*
import za.co.indrajala.fluid.crypto.java.toDER
import za.co.indrajala.fluid.http.HTTP
import za.co.indrajala.fluid.model.device.*

class Fluid(
    host: String,
    port: Int,
) {
    companion object {
        private const val RootKeyAlias = "fluid.root"
    }

    init {
        log.v_header("Fluid Integrity & Confidentiality - (C) 2020, Indrajala (Pty) Ltd", 80, '=')
        check(AndroidKeyStore.initialize())

        HTTP.configure("http", host, port, HTTP.Companion.LogLevel.Verbose)
    }

    // device registration

    private fun indicateIntentToRegisterDevice(
        fingerprint: DeviceFingerprint
    ) {
        HTTP.post(
            "/device/register/intent",
            DevRegInitRq(fingerprint),
            ::handleDevRegIntentRsp
        )
    }

    private fun handleDevRegIntentRsp(json: String?) {

        if (json == null) {
            log.v("null response body received from server")
            return
        }

        val permission = Gson()
            .fromJson(json, DevRegInitRsp::class.java)

        // TODO check that we do indeed have permission

        // generate device root key using received params

        check(AndroidKeyStore.generateDeviceRootKey(
            RootKeyAlias,
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
            if (regResult.registered)
                "device registered"
            else
                "device not registered!"
        )
    }

    fun registerDevice(context: Context) {

        try {

            log.v_header("device fingerprint")
            val deviceFingerprint = DeviceFingerprint.print(context)
            log.v(deviceFingerprint.toString())

            indicateIntentToRegisterDevice(deviceFingerprint)
        } catch (e: Exception) {
            val ee = e;
        }
    }
}