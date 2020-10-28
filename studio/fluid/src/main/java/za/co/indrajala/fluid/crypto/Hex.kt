package za.co.indrajala.fluid.crypto

fun ByteArray.toHex() =
    asUByteArray().toHex()

fun UByteArray.toHex() =
    this.joinToString("") { it.toString(16).padStart(2, '0') }

fun String.toUBytes (): UByteArray =
    Hex.validate(this)
        .chunked(2)
        .map { it.toUByte(16) }
        .toUByteArray()

class Hex {
    companion object {

        val uByteMap: Map<Char, UByte> = mapOf(
            '0' to 0.toUByte(),
            '1' to 1.toUByte(),
            '2' to 2.toUByte(),
            '3' to 3.toUByte(),
            '4' to 4.toUByte(),
            '5' to 5.toUByte(),
            '6' to 6.toUByte(),
            '7' to 7.toUByte(),
            '8' to 8.toUByte(),
            '9' to 9.toUByte(),
            'A' to 10.toUByte(),
            'B' to 11.toUByte(),
            'C' to 12.toUByte(),
            'D' to 13.toUByte(),
            'E' to 14.toUByte(),
            'F' to 15.toUByte()
        )

        fun validate(hex: String): String {
            if (hex.length % 2 != 0)
                throw IllegalArgumentException("odd length ${hex.length}")

            // TODO check for illegal chars

            return hex
        }
    }
}


