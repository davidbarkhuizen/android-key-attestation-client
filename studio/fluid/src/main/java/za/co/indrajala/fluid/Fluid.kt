package za.co.indrajala.fluid

import android.content.Context
import com.google.gson.Gson
import za.co.indrajala.fluid.asn1_poc.DER
import za.co.indrajala.fluid.attestation.KeyDescription
import za.co.indrajala.fluid.bit.hexToUBytes
import za.co.indrajala.fluid.crypto.*
import za.co.indrajala.fluid.crypto.java.X509
import za.co.indrajala.fluid.crypto.java.summary
import za.co.indrajala.fluid.crypto.java.toDER
import za.co.indrajala.fluid.crypto.java.toPEM
import za.co.indrajala.fluid.http.HTTP
import za.co.indrajala.fluid.model.device.*
import za.co.indrajala.fluid.model.rqrsp.DeviceRegPermissionRq
import za.co.indrajala.fluid.model.rqrsp.DeviceRegPermissionRsp
import za.co.indrajala.fluid.model.rqrsp.DeviceRegRq
import za.co.indrajala.fluid.model.rqrsp.DeviceRegRsp

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

        DER.parse("3081f10201020a01010201030a01010408dd4490c65d7f3b3504003056bf853d080206017596adf018bf85454604443042311c301a04157a612e636f2e696e6472616a616c612e666c756964020101312204207b6d3688d13ef0b621464e05dc712a4c62e34707388a52aeb61c35238da94f14307fa1083106020102020103a203020101a30402020800a5053103020106a6053103020103bf8148050203010001bf8377020500bf853e03020100bf853f020500bf85402a30280420dfc2920c81e136fdd2a510478fda137b262dc51d449edd7d0bdb554745725cfe0101ff0a0100bf85410502030186a0bf8542050203031519")
    }

    // device registration

    private fun requestPermissionToRegisterDevice(
        fingerprint: DeviceFingerprint
    ) {
        HTTP.post(
            "/device-registration/permission",
            DeviceRegPermissionRq(fingerprint),
            ::handlePermissionToRegisterDevice
        )
    }

    private fun handlePermissionToRegisterDevice(json: String?) {

        if (json == null) {
            log.v("null response body received from server")
            return
        }

        val permission = Gson()
            .fromJson(json, DeviceRegPermissionRsp::class.java)

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

        chain.forEachIndexed { index, it ->

            log.v_header("CERT $index")

            val x509 = X509.fromPEM(it.toPEM())

            log.v("X509", x509.summary())

            val kd = KeyDescription.fromX509Cert(x509)
            if (kd != null)
                log.v("Key Description", kd.summary())

            log.v_rjust("DER")
            log.v(it.toDER())
        }

        HTTP.post(
            "/device-registration/register",
            DeviceRegRq(
                permission.registrationID,
                chain.map { it.toDER() },
            ),
            ::handleDeviceRegistrationResponse
        )
    }

    private fun handleDeviceRegistrationResponse(json: String?) {
        val regResult = Gson()
            .fromJson(json!!, DeviceRegRsp::class.java)

        log.v(
            if (regResult.registered)
                "device registered"
            else
                "device not registered!"
        )
    }

    fun initiateDeviceRegistration(context: Context) {

        try {

            log.v_header("device fingerprint")
            val deviceFingerprint = DeviceFingerprint.print(context)
            log.v(deviceFingerprint.toString())

            requestPermissionToRegisterDevice(deviceFingerprint)
        } catch (e: Exception) {
            val ee = e;
        }
    }
}