package za.co.indrajala.fluid.crypto

import android.security.keystore.KeyInfo

fun KeyInfo.describe() : String =
    listOf(
        "alias: $keystoreAlias",
        "size (bits): $keySize",
        "isInsideSecureHardware: $isInsideSecureHardware",
        "signature padding(s): ${signaturePaddings.joinToString(", ")}",
        "encryption padding(s): ${encryptionPaddings.joinToString(", ")}"
    ).joinToString("\n")