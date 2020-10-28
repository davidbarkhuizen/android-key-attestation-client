package za.co.indrajala.fluid.asn1

import za.co.indrajala.fluid.ubyte.toUBytes

class DER {

    companion object {

        fun parseIdentifierBytes(hex: String): IdentifierOctet {

            val ido = IdentifierOctet(hex.toUBytes()[0], true)
            return ido
        }

        fun parse(hex: String): Boolean {

            val identifier = parseIdentifierBytes(hex)

            return false
        }
    }
}