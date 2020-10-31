package za.co.indrajala.fluid.bit

fun UByteArray.toHex() =
    this.joinToString("") { it.toString(16).padStart(2, '0') }