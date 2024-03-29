package za.co.indrajala.fluid

import android.content.Context
import android.security.keystore.StrongBoxUnavailableException
import com.google.gson.Gson
import za.co.indrajala.fluid.attestation.KeyDescription
import za.co.indrajala.fluid.crypto.*
import za.co.indrajala.fluid.crypto.java.X509
import za.co.indrajala.fluid.crypto.java.summary
import za.co.indrajala.fluid.crypto.java.toDER
import za.co.indrajala.fluid.crypto.java.toPEM
import za.co.indrajala.fluid.http.HTTP
import za.co.indrajala.fluid.model.DeviceFingerprint
import za.co.indrajala.fluid.model.rqrsp.KeyAttestationInitRq
import za.co.indrajala.fluid.model.rqrsp.KeyAttestationInitRsp
import za.co.indrajala.fluid.model.rqrsp.KeyAttestationRq
import za.co.indrajala.fluid.model.rqrsp.KeyAttestationRsp

class Fluid(
    var host: String,
    var port: Int,
) {
    companion object {
        private const val RootKeyAlias = "fluid.root"
    }

    init {
        log.v_header("Fluid Integrity & Confidentiality - (C) 2020, Indrajala (Pty) Ltd", 80, '=')
        check(AndroidKeyStore.initialize())

        HTTP.configure("http", host, port)

        //DER.parse("3081f10201020a01010201030a01010408dd4490c65d7f3b3504003056bf853d080206017596adf018bf85454604443042311c301a04157a612e636f2e696e6472616a616c612e666c756964020101312204207b6d3688d13ef0b621464e05dc712a4c62e34707388a52aeb61c35238da94f14307fa1083106020102020103a203020101a30402020800a5053103020106a6053103020103bf8148050203010001bf8377020500bf853e03020100bf853f020500bf85402a30280420dfc2920c81e136fdd2a510478fda137b262dc51d449edd7d0bdb554745725cfe0101ff0a0100bf85410502030186a0bf8542050203031519")
    }

    // device registration

    private fun initiateKeyAttestationAtServer(
        fingerprint: DeviceFingerprint
    ) {
        HTTP.post(
            "/attestation/key/init",
            KeyAttestationInitRq(fingerprint),
            ::handleKeyAttInitRspFromServer
        )
    }

    private fun handleKeyAttInitRspFromServer(json: String?, error: Boolean) {

        if (error) {
            log.v("error initiating key attestation ")
            return
        }

        if (json == null) {
            log.v("null response body received from server")
            return
        }

        val rsp = Gson()
            .fromJson(json, KeyAttestationInitRsp::class.java)

        if (!rsp.succeeded) {
            log.v("server rejected key attestation initiation request")
            return
        }

        var generated = false
        try {
            generated = AndroidKeyStore.generateHwAttestedKey(RootKeyAlias, rsp.keyParams)
        } catch (e: StrongBoxUnavailableException) {
            log.e("key generation failed: no strong box", e)
        } catch (e: Exception) {
            log.e("key generation failed: general exception", e)
        }

        if (!generated) {
            // TODO report failures back to server, don't leave entry open
            log.v("terminating on key generation failure")
            return
        }
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

        // TODO handle time difference between phone and server
        Thread.sleep(50)

        HTTP.post(
            "/attestation/key/attest",
            KeyAttestationRq(
                rsp.reference,
                chain.map { it.toDER() },
            ),
            ::handleKeyAttestationRsp
        )
    }

    private fun handleKeyAttestationRsp(json: String?, error: Boolean) {

        if (error) {
            log.v("error completing key attestation ")
            return
        }

        val regResult = Gson()
            .fromJson(json!!, KeyAttestationRsp::class.java)

        log.v(
            if (regResult.registered)
                "device registered"
            else
                "device not registered!"
        )
    }

    fun generateAndAttestKey(context: Context) {

        try {

            log.v_header("device fingerprint")
            val deviceFingerprint = DeviceFingerprint.print(context)
            log.v(deviceFingerprint.toString())

            initiateKeyAttestationAtServer(deviceFingerprint)
        } catch (e: Exception) {
            val ee = e;
        }
    }
}