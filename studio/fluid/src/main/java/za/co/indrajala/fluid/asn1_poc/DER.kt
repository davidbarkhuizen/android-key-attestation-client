package za.co.indrajala.fluid.asn1_poc

import za.co.indrajala.fluid.ubyte.bitsAreSet
import za.co.indrajala.fluid.ubyte.getStandAloneBitsValue
import za.co.indrajala.fluid.ubyte.hexToUBytes

class DER {
    companion object {

        fun parseOID(bytes: UByteArray) {

            val firstByte = bytes[0]
            println(firstByte.toString(16))

            val firstNodeValue = firstByte / 40.toUByte()
            val secondNodeValue = firstByte - (firstNodeValue * 40.toUInt())

            val nodes = arrayListOf<ULong>(firstNodeValue.toULong(), secondNodeValue.toULong())

            var remainder = bytes.map { it }.takeLast(bytes.size - 1)

            while (remainder.isNotEmpty()) {

                val isLongForm = remainder[0].bitsAreSet(8)

                if (!isLongForm) {
                    nodes.add(remainder[0].toULong())
                    remainder = remainder.takeLast(remainder.size - 1)
                } else {

                    val head = remainder.takeWhile { it.bitsAreSet(8) }.toTypedArray()

                    val unpacked = listOf(
                        *head,
                        remainder[head.size]
                    ).map { it.toString(radix = 2).padStart(8, '0').takeLast(7) }
                        //.asReversed()
                        .joinToString("")

                    remainder = remainder.takeLast(remainder.size - (head.size + 1))

                    val packed =
                        if (unpacked.length % 8 == 0)
                            unpacked
                        else
                            "0".repeat(8 - (unpacked.length % 8)) + unpacked

                    val oid = packed.toULong(radix = 2)
                    nodes.add(oid)
                }
            }

            println("OID: ${nodes.joinToString(".")}")
        }

        fun parse(hex: String) {

            println("raw: $hex")

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

            // parse length bytes

            val firstLengthByte = remainder[0]
            remainder = remainder.takeLast(remainder.size - 1)

            val longFormLength = firstLengthByte.bitsAreSet(8)

            println(if (longFormLength) "long form length" else "short form length")

            val length: ULong = if (!longFormLength) {
                firstLengthByte.getStandAloneBitsValue(1,2,3,4,5,6,7).toULong()
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

            val content = remainder.take(length.toInt())
            val contentHex = content.joinToString(separator = "", transform = { it.toString(16).padStart(2, '0') })

            remainder = remainder.takeLast(remainder.size - length.toInt())

            if (construction == Asn1Construction.Constructed) {
                println("parsing next layer of constructed element")
                println("-".repeat(60))
                parse(contentHex)
            } else {
                println("content: $contentHex")

                if (initialOctetTag == Asn1Tag.object_identifier) {
                    parseOID(contentHex.hexToUBytes())
                }
            }

            println("=".repeat(60))
            if (remainder.isNotEmpty()) {
                parse(remainder.joinToString(separator = "", transform = { it.toString(16).padStart(2, '0') }))
            }
        }
    }
}