package za.co.indrajala.fluid.crypto.der

import za.co.indrajala.fluid.crypto.toUBytes

class DER {

    companion object {
        fun parse(hex: String) {
            val bytes = hex.toUBytes()
        }
    }
}