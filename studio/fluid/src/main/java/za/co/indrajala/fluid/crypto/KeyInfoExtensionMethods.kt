package za.co.indrajala.fluid.crypto

import android.security.keystore.KeyInfo

fun KeyInfo.describe() : String =
    listOf(
        "KS Alias: $keystoreAlias",
        "Size (bits): $keySize",
        "Sig Padding: ${signaturePaddings.joinToString(", ")}",
        "EncDec Padding: ${encryptionPaddings.joinToString(", ")}"
    ).joinToString("\n")