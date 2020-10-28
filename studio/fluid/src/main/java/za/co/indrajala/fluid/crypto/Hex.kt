package za.co.indrajala.fluid.crypto

fun ByteArray.toHex() =
    asUByteArray().toHex()

fun UByteArray.toHex() =
    this.joinToString("") { it.toString(16).padStart(2, '0') }

class Hex {
    companion object {

        private val ubyteMap: Map<Char, UByte> = mapOf(
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

        fun validate(hex: String){
            if (hex.length % 2 != 0)
                throw IllegalArgumentException("odd length ${hex.length}")
        }

        fun clean(hex: String) =
            hex.toUpperCase()

        fun toUBytes (hex: String): UByteArray {
            validate(hex)

            return clean(hex)
                .chunked(2)
                .map {

                    val i = ubyteMap[it[0]]!!
                    val j = ubyteMap[it[1]]!!

                    val ii = i * 16.toUByte()
                    val iii = ii.toUByte()

                    val x = iii + j

                    x
                }
                .map {
                    it.toUByte()
                }
                .toUByteArray()
        }
    }
}


