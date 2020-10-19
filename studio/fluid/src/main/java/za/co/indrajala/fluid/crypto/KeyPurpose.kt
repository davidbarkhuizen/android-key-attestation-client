package za.co.indrajala.fluid.crypto

import android.security.keystore.KeyProperties

enum class KeyPurpose(val purpose: Int) {
    Confidentiality(KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT),
    Integrity(KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
}