package za.co.indrajala.fluid.crypto

import za.co.indrajala.fluid.ubyte.toHex
import java.security.cert.X509Certificate

fun X509Certificate.summary(): List<Pair<String, String?>> = listOf(
    Pair("Issuer Name (DN)", issuerDN.name),
    // issuer alt names
    Pair("Subject Name (DN)", subjectDN.name),
    // subject alt names

    Pair("Version", version.toString()),
    Pair("S/N", serialNumber.toString()),
    Pair("Not Before", notBefore.toString()),
    Pair("Not After", notAfter.toString()),

    Pair("Sig Algorithm", sigAlgName),
    Pair("Sig Algorithm OID", sigAlgOID),
    Pair("Signature", signature.toHex()),
    Pair("Subject Pub Key Algorithm", publicKey.algorithm),
    Pair("Subject Pub Key", publicKey.encoded.toHex()),

    // TODO keyUsage
    // TODO Issuer Unique ID
    // TODO Subject Unique ID
)