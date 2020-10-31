package za.co.indrajala.fluid.bit

fun ByteArray.toHex() =
    this.joinToString("") { it.toString(16).padStart(2, '0') }