package za.co.indrajala.fluid.asn1

import za.co.indrajala.fluid.ubyte.bitsAreSet
import za.co.indrajala.fluid.ubyte.getStandAloneBitsValue
import za.co.indrajala.fluid.ubyte.hexToUBytes

class DER {

    companion object {

        fun parse(hex: String): Boolean {

            val raw = hex.hexToUBytes()

            val b = raw[0]

            println("b1 $b ${b.toString(radix = 2)}")

            val idClass = Asn1Class.fromValue(b.getStandAloneBitsValue(8,7))
            println("class $idClass")

            val construction = Asn1Construction.fromValue(b.getStandAloneBitsValue(6))
            println("construction $construction")

            // TODO validate that construction is permitted for tag

            val initialOctetTag = Asn1Tag.fromValue(b.getStandAloneBitsValue(1,2,3,4,5).toULong())
            println("initialTagOctet $initialOctetTag")

            var remainder: List<UByte> = raw.takeLast(raw.size - 1)

            var longTag: Asn1Tag? = null

            // parse long tag if required
            //
            if (initialOctetTag.value == 31.toULong()) {
                // ==> tag coded over one or more subsequent bytes

                var subsequentIdentifierTagBytes: ArrayList<UByte> = arrayListOf()

                var more = true
                while (more) {
                    subsequentIdentifierTagBytes.add(remainder[0])
                    remainder = remainder.takeLast(remainder.size - 1)
                    more = remainder.isNotEmpty() && remainder[0].bitsAreSet(8)
                }

                println("subsequentIdentifierTagBytes:")
                subsequentIdentifierTagBytes.forEach {
                    println(it)
                }

                var subsequentTag7BitStrings = subsequentIdentifierTagBytes
                    .map { it.toString(radix = 2).padStart(8, '0').takeLast(7) }

                println("subsequentTag7BitStrings:")
                subsequentTag7BitStrings.forEach {
                    println(it)
                }

                val tagBits = subsequentTag7BitStrings.asReversed().joinToString("")

                println("tagBits, $tagBits")

                val tagBitsPackedToNearestByte =
                    if (tagBits.length % 8 == 0)
                        tagBits
                    else
                        "0".repeat(8 - (tagBits.length % 8)) + tagBits

                println("tagBitsPackedToNearestByte, $tagBitsPackedToNearestByte")

                val tagNumber = tagBitsPackedToNearestByte.toULong(radix = 2)
                println("tagNumber $tagNumber")

                longTag = Asn1Tag.fromValue(tagNumber)
                println(longTag)
            }

            println("remainder ${remainder.map { it.toString(16) }.joinToString("")}")

            // parse length bytes

            val firstLengthByte = remainder[0]
            remainder = remainder.takeLast(remainder.size - 1)

            val longFormLength = firstLengthByte.bitsAreSet(8)

            println(if (longFormLength) "long form length" else "short form length")

            val length: ULong = if (!longFormLength) {
                firstLengthByte.getStandAloneBitsValue().toULong()
            } else {
                val numberOfSubsequentLengthBytes = firstLengthByte.getStandAloneBitsValue(1,2,3,4,5,6,7).toInt()

                println("$numberOfSubsequentLengthBytes subsequent length bytes")

                val lengthBytes = remainder.take(numberOfSubsequentLengthBytes)

                remainder = remainder.takeLast(remainder.size - numberOfSubsequentLengthBytes)

                lengthBytes
                    .map { it.toString(16).padStart(2, '0') }
                    .joinToString("")
                    .toULong(16)
            }

            println("length $length")

            return false
        }
    }
}