package za.co.indrajala.fluid

import org.junit.Assert
import org.junit.Test
import za.co.indrajala.fluid.ubyte.uByteMask
import za.co.indrajala.fluid.ubyte.shl
import za.co.indrajala.fluid.ubyte.shr

class BitWiseTests {

    // assuming BE, i.e. 87654321, and not 12345678

    @Test
    fun shl() {

        val one = 1.toUByte()
        Assert.assertEquals(one.shl(1), 2.toUByte())
        Assert.assertEquals(one.shl(2), 4.toUByte())
        Assert.assertEquals(one.shl(3), 8.toUByte())
        Assert.assertEquals(one.shl(4), 16.toUByte())
        Assert.assertEquals(one.shl(5), 32.toUByte())
        Assert.assertEquals(one.shl(6), 64.toUByte())
        Assert.assertEquals(one.shl(7), 128.toUByte())
        Assert.assertEquals(one.shl(8), 1.toUByte())

        val three = 3.toUByte()
        Assert.assertEquals(three.shl(2), 12.toUByte())
    }

    @Test
    fun shr() {
        val one = 1.toUByte()
        Assert.assertEquals(one.shr(1), 128.toUByte())

        val three = 3.toUByte()
        Assert.assertEquals(three.shr(2), (128 + 64).toUByte())
    }

    @Test
    fun mask() {
        val twoFiveFive = 255.toUByte()
        Assert.assertEquals(127.toUByte(), uByteMask(1,2,3,4,5,6,7) and twoFiveFive)
        Assert.assertEquals(128.toUByte(), uByteMask(8) and twoFiveFive)
    }
}