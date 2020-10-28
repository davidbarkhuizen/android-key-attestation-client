package za.co.indrajala.fluid.ubyte

fun ByteArray.toHex() =
    asUByteArray().toHex()

fun UByteArray.toHex() =
    this.joinToString("") { it.toString(16).padStart(2, '0') }

fun String.hexToUBytes (): UByteArray =
    Hex.validate(this)
        .chunked(2)
        .map { it.toUByte(16) }
        .toUByteArray()

class Hex {
    companion object {
        fun validate(hex: String): String {
            if (hex.length % 2 != 0)
                throw IllegalArgumentException("odd length ${hex.length}")

            // TODO check for illegal chars

            return hex
        }
    }
}


