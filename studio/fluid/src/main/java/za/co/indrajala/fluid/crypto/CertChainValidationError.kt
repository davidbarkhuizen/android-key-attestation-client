package za.co.indrajala.fluid.crypto

enum class CertChainValidationError {
    None,
    NoRoot,
    MoreThanOneRoot,
    BrokenChain,
    CertificateExpired,
    CertificateNotYetValid,
    BadSignature,
    UnableToValidateSignature
}