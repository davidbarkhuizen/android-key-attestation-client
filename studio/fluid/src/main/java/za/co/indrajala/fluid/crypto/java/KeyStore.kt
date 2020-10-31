package za.co.indrajala.fluid.crypto.java

import java.security.KeyStore

fun KeyStore.summary() : String =
        "Security Provider: $provider, Type $type, Key Count ${this.size()}"