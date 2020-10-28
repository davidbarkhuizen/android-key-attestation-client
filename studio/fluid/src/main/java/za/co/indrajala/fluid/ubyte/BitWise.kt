package za.co.indrajala.fluid.ubyte

//infix inline
fun UByte.shl(shift: Int): UByte {

    if (shift == 0)
        return this

//    println("$this SHL $shift")

    val binary = this.toString(radix = 2).padStart(8, '0')

//    println("binary $this $binary")

    val rotatedBinary = binary.takeLast(binary.length - shift) + binary.take(shift)

    val shifted = rotatedBinary.toUByte(2)

//    println("shifted $rotatedBinary $shifted")

    return shifted
}

fun UByte.shr(shift: Int): UByte {

    if (shift == 0)
        return this

    println("base value $this")

    val binary = this.toString(radix = 2).padStart(8, '0')

    println("binary $binary")

    val rotatedBinary = binary.takeLast(shift) + binary.take(binary.length - shift)

    println("rotated $rotatedBinary")

    val shifted = rotatedBinary.toUByte(2)

    println("shifted $shifted")

    return shifted
}

fun UByteMask(vararg bits: Int): UByte {

    var byteMask: UByte = 0.toUByte()

//    println("building bytemask...")

    bits.forEach {
        val bitMask = 1.toUByte().shl(it - 1)
        byteMask = byteMask or bitMask
    }

//    println("=> bytemask $byteMask")

    return byteMask
}

fun UByte.getStandAloneBitsValue(vararg bits: Int): UByte =
    (this and UByteMask(*bits)).shr(bits.minOf { it } - 1)



