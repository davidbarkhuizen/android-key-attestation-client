package za.co.indrajala.fluid.attestation.enums
import com.google.gson.annotations.SerializedName;

enum class Digest(val value: Int) {

    @SerializedName("0")
    NONE(0),

    @SerializedName("1")
    MD5(1),

    @SerializedName("2")
    SHA1(2),

    @SerializedName("3")
    SHA_2_224(3),

    @SerializedName("4")
    SHA_2_256(4),

    @SerializedName("5")
    SHA_2_384(5),

    @SerializedName("6")
    SHA_2_512(6);

    companion object {
        private val map = Digest.values().associateBy(Digest::value)
        fun fromValue(value: Int): Digest {
            return map[value] ?: error("$value")
        }
    }
}