package za.co.indrajala.fluid.crypto

import java.security.KeyStore

fun KeyStore.describe() : String =
        "Security Provider: $provider, Type $type, Key Count ${this.size()}"