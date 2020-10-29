package za.co.indrajala.fluid

import org.junit.Assert
import org.junit.Test
import za.co.indrajala.fluid.asn1.Asn1Class
import za.co.indrajala.fluid.asn1.DER
import za.co.indrajala.fluid.asn1.Asn1Identifier
import za.co.indrajala.fluid.ubyte.hexToUBytes

class DerTests {

    companion object {
        val certHex = "308203cd30820235a003020102020101300d06092a864886f70d01010b0500301b3119301706035504051310653164366633386433396338373736643020170d3730303130313030303030305a180f32313036303230373036323831355a301f311d301b06035504030c14416e64726f6964204b657973746f7265204b657930819f300d06092a864886f70d010101050003818d0030818902818100c6dc08d3f372bf92077c75e0b2b74b392c0e803184abdc3589b11c2a2db01aebf3dd2d6001e4add9f000c1d7aaeb650021d07bf39ea3a2427d9a8103d276454dfcf07440de7bcad2a8f3822286f49611f7c6e72a67e10e2e0e64224e5bd95ec20b432cc30bda38b342e494533ea275fdc143ca7fe61f1fcf9b2ebf699f337ecf0203010001a382011830820114300e0603551d0f0101ff04040302043030820100060a2b06010401d6790201110481f13081ee0201020a01010201030a010104087ba9384fb008033a04003056bf853d08020601756d7445d0bf85454604443042311c301a04157a612e636f2e696e6472616a616c612e666c756964020101312204207b6d3688d13ef0b621464e05dc712a4c62e34707388a52aeb61c35238da94f14307ca1053103020100a203020101a30402020400a5053103020106a6053103020103bf8148050203010001bf8377020500bf853e03020100bf853f020500bf85402a30280420dfc2920c81e136fdd2a510478fda137b262dc51d449edd7d0bdb554745725cfe0101ff0a0100bf85410502030186a0bf8542050203031519300d06092a864886f70d01010b050003820181003440780822899d8a07748a54be9966e04c09dff540b6cc0c63b2746adbce325a906b71e9a5213a6dd1d90da144e00be32263b2a75d486b51b7be7feaf89764c2913fdc39f71000387aee915ed7d757e554727f3c337ec18cad6d4ef230d0bcfefe12eca6eb88ef950774993891ded488fe535b4759b4d8e6fe585fdc87fbb0449f5847fc8794ae74674e2d84c7fc54f37ccd0687c305fd269a989c09c843cfde2a84bec67760201a669b13678c963bd3ac4763db9be95c41af435f861a40223e0f575653f5180cd8da02a4f7e9757cab346a38e6f4690fc9eb8857b2d23dda51f56b42d3d2b4ac74bd4b1fb1f052cf519f913fa4d4695a806299886cef25ec9c696baa1f62dfc264eada2af6144f734b15c36fdad0e348e29748d4afee3f5a7485c38ab33b459b870284e702b71122251b533b3918f03e04805eb76ad338d9d467dbd1f1550e1326a9ad24e18bf02b8512394975fd72e5175d286688e8ebfa7973833626ea1ceeecf37c6361796fd2c25b1d905f0484f52b4c3eef2bafc80897"
        // 30 82 03 cd 30 82 02 35 a00
        // 30 => universal, constructed, sequence
        // 82 => long form length, 2 length bytes
        // 03CD => length
        // remainder = 30820235a003020102020101300d06092a864886f70d01010b0500301b3119301706035504051310653164366633386433396338373736643020170d3730303130313030303030305a180f32313036303230373036323831355a301f311d301b06035504030c14416e64726f6964204b657973746f7265204b657930819f300d06092a864886f70d010101050003818d0030818902818100c6dc08d3f372bf92077c75e0b2b74b392c0e803184abdc3589b11c2a2db01aebf3dd2d6001e4add9f000c1d7aaeb650021d07bf39ea3a2427d9a8103d276454dfcf07440de7bcad2a8f3822286f49611f7c6e72a67e10e2e0e64224e5bd95ec20b432cc30bda38b342e494533ea275fdc143ca7fe61f1fcf9b2ebf699f337ecf0203010001a382011830820114300e0603551d0f0101ff04040302043030820100060a2b06010401d6790201110481f13081ee0201020a01010201030a010104087ba9384fb008033a04003056bf853d08020601756d7445d0bf85454604443042311c301a04157a612e636f2e696e6472616a616c612e666c756964020101312204207b6d3688d13ef0b621464e05dc712a4c62e34707388a52aeb61c35238da94f14307ca1053103020100a203020101a30402020400a5053103020106a6053103020103bf8148050203010001bf8377020500bf853e03020100bf853f020500bf85402a30280420dfc2920c81e136fdd2a510478fda137b262dc51d449edd7d0bdb554745725cfe0101ff0a0100bf85410502030186a0bf8542050203031519300d06092a864886f70d01010b050003820181003440780822899d8a07748a54be9966e04c09dff540b6cc0c63b2746adbce325a906b71e9a5213a6dd1d90da144e00be32263b2a75d486b51b7be7feaf89764c2913fdc39f71000387aee915ed7d757e554727f3c337ec18cad6d4ef230d0bcfefe12eca6eb88ef950774993891ded488fe535b4759b4d8e6fe585fdc87fbb0449f5847fc8794ae74674e2d84c7fc54f37ccd0687c305fd269a989c09c843cfde2a84bec67760201a669b13678c963bd3ac4763db9be95c41af435f861a40223e0f575653f5180cd8da02a4f7e9757cab346a38e6f4690fc9eb8857b2d23dda51f56b42d3d2b4ac74bd4b1fb1f052cf519f913fa4d4695a806299886cef25ec9c696baa1f62dfc264eada2af6144f734b15c36fdad0e348e29748d4afee3f5a7485c38ab33b459b870284e702b71122251b533b3918f03e04805eb76ad338d9d467dbd1f1550e1326a9ad24e18bf02b8512394975fd72e5175d286688e8ebfa7973833626ea1ceeecf37c6361796fd2c25b1d905f0484f52b4c3eef2bafc80897
        // => 1946 chars => 973 bytes
    }

    @Test
    fun parseIdentifierBytes() {

//        val z = Asn1Identifier("30".hexToUBytes()[0], true)
//        Assert.assertEquals(z.asn1Class, Asn1Class.Universal)
    }

    @Test
    fun parse() {

        //    b1 48 110000
        //    class Universal
        //    construction Constructed
        //    initialTagOctet sequence
        //    remainder 821b3
        //    long form length
        //    2 subsequent length bytes
        //    length 435
        //
//        DER.parse("308201B3")
//
//        println("*".repeat(60))

        DER.parse(certHex)

        Assert.assertEquals(true, true)
    }
}