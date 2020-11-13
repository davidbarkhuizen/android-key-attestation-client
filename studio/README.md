TODO
- secure import of public key generated server-side
- remote key attestation
- performance profiling (key gen, enc, dec, sign, verify)

-------------------------------

json model definition out of sync


E/AndroidRuntime: FATAL EXCEPTION: OkHttp Dispatcher
    Process: za.co.indrajala.fluid, PID: 12912
    java.lang.NullPointerException: Parameter specified as non-null is null: method kotlin.jvm.internal.Intrinsics.checkNotNullParameter, parameter registrationID
        at za.co.indrajala.fluid.model.rqrsp.DeviceRegRq.<init>(Unknown Source:2)
        at za.co.indrajala.fluid.Fluid.handlePermissionToRegisterDevice(Fluid.kt:91)
        at za.co.indrajala.fluid.Fluid.access$handlePermissionToRegisterDevice(Fluid.kt:20)
        at za.co.indrajala.fluid.Fluid$requestPermissionToRegisterDevice$1.invoke(Fluid.kt:45)
        at za.co.indrajala.fluid.Fluid$requestPermissionToRegisterDevice$1.invoke(Fluid.kt:20)
        at za.co.indrajala.fluid.http.HTTP$Companion$post$callBacks$1.onResponse(HTTP.kt:66)
        at okhttp3.internal.connection.RealCall$AsyncCall.run(RealCall.kt:519)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)
        at java.lang.Thread.run(Thread.java:919)



-------------------------------

server returned non JSON body (html, text) in response to route not existing

E/AndroidRuntime: FATAL EXCEPTION: OkHttp Dispatcher
    Process: za.co.indrajala.fluid, PID: 3964
    com.google.gson.JsonSyntaxException: java.lang.IllegalStateException: Expected BEGIN_OBJECT but was STRING at line 1 column 1 path $
        at com.google.gson.internal.bind.ReflectiveTypeAdapterFactory$Adapter.read(ReflectiveTypeAdapterFactory.java:226)
        at com.google.gson.Gson.fromJson(Gson.java:932)
        at com.google.gson.Gson.fromJson(Gson.java:897)
        at com.google.gson.Gson.fromJson(Gson.java:846)
        at com.google.gson.Gson.fromJson(Gson.java:817)
        at za.co.indrajala.fluid.Fluid.handlePermissionToRegisterDevice(Fluid.kt:57)
        at za.co.indrajala.fluid.Fluid.access$handlePermissionToRegisterDevice(Fluid.kt:20)
        at za.co.indrajala.fluid.Fluid$requestPermissionToRegisterDevice$1.invoke(Fluid.kt:45)
        at za.co.indrajala.fluid.Fluid$requestPermissionToRegisterDevice$1.invoke(Fluid.kt:20)
        at za.co.indrajala.fluid.http.HTTP$Companion$post$callBacks$1.onResponse(HTTP.kt:66)
        at okhttp3.internal.connection.RealCall$AsyncCall.run(RealCall.kt:519)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)
        at java.lang.Thread.run(Thread.java:919)
     Caused by: java.lang.IllegalStateException: Expected BEGIN_OBJECT but was STRING at line 1 column 1 path $
        at com.google.gson.stream.JsonReader.beginObject(JsonReader.java:386)
        at com.google.gson.internal.bind.ReflectiveTypeAdapterFactory$Adapter.read(ReflectiveTypeAdapterFactory.java:215)
        at com.google.gson.Gson.fromJson(Gson.java:932) 
        at com.google.gson.Gson.fromJson(Gson.java:897) 
        at com.google.gson.Gson.fromJson(Gson.java:846) 
        at com.google.gson.Gson.fromJson(Gson.java:817) 
        at za.co.indrajala.fluid.Fluid.handlePermissionToRegisterDevice(Fluid.kt:57) 
        at za.co.indrajala.fluid.Fluid.access$handlePermissionToRegisterDevice(Fluid.kt:20) 
        at za.co.indrajala.fluid.Fluid$requestPermissionToRegisterDevice$1.invoke(Fluid.kt:45) 
        at za.co.indrajala.fluid.Fluid$requestPermissionToRegisterDevice$1.invoke(Fluid.kt:20) 
        at za.co.indrajala.fluid.http.HTTP$Companion$post$callBacks$1.onResponse(HTTP.kt:66) 
        at okhttp3.internal.connection.RealCall$AsyncCall.run(RealCall.kt:519) 
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167) 
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641) 
        at java.lang.Thread.run(Thread.java:919) 


=> use SoftHSM for server-side work, to support automated testing

# Fluid Authentication & Authorization

## Glossary

acronym|expansion
-------|---------
AKS|Android Keystore System  
HAL|(Android) Harware Abstraction Layer

## Test Phones

### Summary Comparison of Relevant Security Features

phone|HW-backed|StrongBox-backed|1024 RSA|2048 RSA
-----|----------------|-----------------|--------|--------
Nokia 6.1|Y|N|203 ms|939 ms

### Nokia 6.1

label|text
-----|----
released|May 2018
body dimensions|148.8 x 75.8 x 8.2 mm
release OS|Android 8.1
chipset|Qualcomm SDM630 Snapdragon 630 (14 nm)
CPU|Octa-core 2.2 GHz Cortex-A53
GPU|Adreno 508
RAM|32GB 3GB RAM, 32GB 4GB RAM, 64GB 4GB RAM eMMC 5.1
USB port|C
NFC|yes

## Android KeyStore

security functionality
- prevention of extraction of key material, from
  - application process
  - physical device as a whole
- enforcement of key usage constraints

isolation of crypto keys and operations
- crypto ops never performed within the application process
  - i.e. process isolation
  - at worst ops performed my os process, at best in dedicated harware secure element

### important aspects

KeyInfo.isInsideSecureHardware vs KeySpec.isStrongBoxBacked 

KeyInfo.isInsideSecureHardware
=> key material resides in SEE or TEE

(TODO what is the actual SEE/TEE for the N6.1

## Android API

KeyInfo 
- implements KeySpec
- description generated by AKS
- common interface for symmetric (SecretKey) and assymetric (PrivateKey)

.getUserAuthenticationType() =  
KeyProperties[AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL]  

### StrongBox Low Power SubSuite 

Cipher|Key Size (bit)
RSA|2048
AES|128,256
ECDSA|P-256
HMAC-SHA256|64 - 512 (8 - 64 bytes)
Triple DES|168

## Relevant ASN.1 X.509 Object Identifiers (OIDs)

1.2.840.113549.1.1.11     sha256WithRSAEncryption   PKCS #1       
2.5.4.5                   serialNumber              X.520 DN component    printable string
2.5.4.3                   commonName                X.520 DN component    utf8 string

## Google Key Attestation

### Attestation X.509 Cert Extension Schemas

#### Attestation v3 Schema

```
KeyDescription ::= SEQUENCE {
    attestationVersion  3,
    attestationSecurityLevel  SecurityLevel,
    keymasterVersion  INTEGER,
    keymasterSecurityLevel  SecurityLevel,
    attestationChallenge  OCTET_STRING,
    uniqueId  OCTET_STRING,
    softwareEnforced  AuthorizationList,
    teeEnforced  AuthorizationList,
}

SecurityLevel ::= ENUMERATED {
    Software  (0),
    TrustedEnvironment  (1),
    StrongBox  (2),
}

AuthorizationList ::= SEQUENCE {
    purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL,
    algorithm  [2] EXPLICIT INTEGER OPTIONAL,
    keySize  [3] EXPLICIT INTEGER OPTIONAL,
    digest  [5] EXPLICIT SET OF INTEGER OPTIONAL,
    padding  [6] EXPLICIT SET OF INTEGER OPTIONAL,
    ecCurve  [10] EXPLICIT INTEGER OPTIONAL,
    rsaPublicExponent  [200] EXPLICIT INTEGER OPTIONAL,
    rollbackResistance  [303] EXPLICIT NULL OPTIONAL,
    activeDateTime  [400] EXPLICIT INTEGER OPTIONAL,
    originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
    usageExpireDateTime  [402] EXPLICIT INTEGER OPTIONAL,
    noAuthRequired  [503] EXPLICIT NULL OPTIONAL,
    userAuthType  [504] EXPLICIT INTEGER OPTIONAL,
    authTimeout  [505] EXPLICIT INTEGER OPTIONAL,
    allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
    trustedUserPresenceRequired  [507] EXPLICIT NULL OPTIONAL,
    trustedConfirmationRequired  [508] EXPLICIT NULL OPTIONAL,
    unlockedDeviceRequired  [509] EXPLICIT NULL OPTIONAL,
    allApplications  [600] EXPLICIT NULL OPTIONAL,
    applicationId  [601] EXPLICIT OCTET_STRING OPTIONAL,
    creationDateTime  [701] EXPLICIT INTEGER OPTIONAL,
    origin  [702] EXPLICIT INTEGER OPTIONAL,
    rootOfTrust  [704] EXPLICIT RootOfTrust OPTIONAL,
    osVersion  [705] EXPLICIT INTEGER OPTIONAL,
    osPatchLevel  [706] EXPLICIT INTEGER OPTIONAL,
    attestationApplicationId  [709] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdBrand  [710] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdDevice  [711] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdProduct  [712] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdSerial  [713] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdImei  [714] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdMeid  [715] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdModel  [717] EXPLICIT OCTET_STRING OPTIONAL,
    vendorPatchLevel  [718] EXPLICIT INTEGER OPTIONAL,
    bootPatchLevel  [719] EXPLICIT INTEGER OPTIONAL,
}

RootOfTrust ::= SEQUENCE {
    verifiedBootKey  OCTET_STRING,
    deviceLocked  BOOLEAN,
    verifiedBootState  VerifiedBootState,
    verifiedBootHash OCTET_STRING,
}

VerifiedBootState ::= ENUMERATED {
    Verified  (0),
    SelfSigned  (1),
    Unverified  (2),
    Failed  (3),
}
```

#### Attestation v2 Schema

```
KeyDescription ::= SEQUENCE {
    attestationVersion  2,
    attestationSecurityLevel  SecurityLevel,
    keymasterVersion  INTEGER,
    keymasterSecurityLevel  SecurityLevel,
    attestationChallenge  OCTET_STRING,
    uniqueId  OCTET_STRING,
    softwareEnforced  AuthorizationList,
    teeEnforced  AuthorizationList,
}

SecurityLevel ::= ENUMERATED {
    Software  (0),
    TrustedEnvironment  (1),
}

AuthorizationList ::= SEQUENCE {
    purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL,
    algorithm  [2] EXPLICIT INTEGER OPTIONAL,
    keySize  [3] EXPLICIT INTEGER OPTIONAL,
    digest  [5] EXPLICIT SET OF INTEGER OPTIONAL,
    padding  [6] EXPLICIT SET OF INTEGER OPTIONAL,
    ecCurve  [10] EXPLICIT INTEGER OPTIONAL,
    rsaPublicExponent  [200] EXPLICIT INTEGER OPTIONAL,
    activeDateTime  [400] EXPLICIT INTEGER OPTIONAL,
    originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
    usageExpireDateTime  [402] EXPLICIT INTEGER OPTIONAL,
    noAuthRequired  [503] EXPLICIT NULL OPTIONAL,
    userAuthType  [504] EXPLICIT INTEGER OPTIONAL,
    authTimeout  [505] EXPLICIT INTEGER OPTIONAL,
    allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
    allApplications  [600] EXPLICIT NULL OPTIONAL,
    applicationId  [601] EXPLICIT OCTET_STRING OPTIONAL,
    creationDateTime  [701] EXPLICIT INTEGER OPTIONAL,
    origin  [702] EXPLICIT INTEGER OPTIONAL,
    rollbackResistant  [703] EXPLICIT NULL OPTIONAL,
    rootOfTrust  [704] EXPLICIT RootOfTrust OPTIONAL,
    osVersion  [705] EXPLICIT INTEGER OPTIONAL,
    osPatchLevel  [706] EXPLICIT INTEGER OPTIONAL,
    attestationApplicationId  [709] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdBrand  [710] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdDevice  [711] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdProduct  [712] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdSerial  [713] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdImei  [714] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdMeid  [715] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdModel  [717] EXPLICIT OCTET_STRING OPTIONAL,
}

RootOfTrust ::= SEQUENCE {
    verifiedBootKey  OCTET_STRING,
    deviceLocked  BOOLEAN,
    verifiedBootState  VerifiedBootState,
}

VerifiedBootState ::= ENUMERATED {
    Verified  (0),
    SelfSigned  (1),
    Unverified  (2),
    Failed  (3),
}
```

#### Attestation v1 Schema

```
KeyDescription ::= SEQUENCE {
    attestationVersion  1,
    attestationSecurityLevel  SecurityLevel,
    keymasterVersion  INTEGER,
    keymasterSecurityLevel  SecurityLevel,
    attestationChallenge  OCTET_STRING,
    uniqueId  OCTET_STRING,
    softwareEnforced  AuthorizationList,
    teeEnforced  AuthorizationList,
}

SecurityLevel ::= ENUMERATED {
    Software  (0),
    TrustedEnvironment  (1),
}

AuthorizationList ::= SEQUENCE {
    purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL,
    algorithm  [2] EXPLICIT INTEGER OPTIONAL,
    keySize  [3] EXPLICIT INTEGER OPTIONAL,
    digest  [5] EXPLICIT SET OF INTEGER OPTIONAL,
    padding  [6] EXPLICIT SET OF INTEGER OPTIONAL,
    ecCurve  [10] EXPLICIT INTEGER OPTIONAL,
    rsaPublicExponent  [200] EXPLICIT INTEGER OPTIONAL,
    activeDateTime  [400] EXPLICIT INTEGER OPTIONAL,
    originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
    usageExpireDateTime  [402] EXPLICIT INTEGER OPTIONAL,
    noAuthRequired  [503] EXPLICIT NULL OPTIONAL,
    userAuthType  [504] EXPLICIT INTEGER OPTIONAL,
    authTimeout  [505] EXPLICIT INTEGER OPTIONAL,
    allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
    allApplications  [600] EXPLICIT NULL OPTIONAL,
    applicationId  [601] EXPLICIT OCTET_STRING OPTIONAL,
    creationDateTime  [701] EXPLICIT INTEGER OPTIONAL,
    origin  [702] EXPLICIT INTEGER OPTIONAL,
    rollbackResistant  [703] EXPLICIT NULL OPTIONAL,
    rootOfTrust  [704] EXPLICIT RootOfTrust OPTIONAL,
    osVersion  [705] EXPLICIT INTEGER OPTIONAL,
    osPatchLevel  [706] EXPLICIT INTEGER OPTIONAL,
}

RootOfTrust ::= SEQUENCE {
    verifiedBootKey  OCTET_STRING,
    deviceLocked  BOOLEAN,
    verifiedBootState  VerifiedBootState,
}

VerifiedBootState ::= ENUMERATED {
    Verified  (0),
    SelfSigned  (1),
    Unverified  (2),
    Failed  (3),
}
```

### CRL

https://android.googleapis.com/attestation/status

#### JSON schema

```
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "entries": {
      "description" : "Each entry represents the status of an attestation key. The dictionary-key is the certificate serial number in lowercase hex.",
      "type": "object",
      "propertyNames": {
         "pattern": "^[a-f0-9]*$"
      },
      "additionalProperties": {
        "type": "object",
        "properties": {
          "status": {
            "description": "[REQUIRED] Current status of the key.",
            "type": "string",
            "enum": ["REVOKED", "SUSPENDED"]
          },
          "expires": {
            "description": "[OPTIONAL] UTC date when certificate expires in ISO8601 format (YYYY-MM-DD). Can be used to clear expired certificates from the status list.",
            "type": "string",
            "format": "date"
          },
          "reason": {
            "description": "[OPTIONAL] Reason for the current status.",
            "type": "string",
            "enum": ["UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW"]
          },
          "comment": {
            "description": "[OPTIONAL] Free form comment about the key status.",
            "type": "string",
            "maxLength": 140
          }
        },
        "required": ["status"],
        "additionalProperties": false
      }
    }
  },
  "required": ["entries"],
  "additionalProperties": false
}
```

#### example

```
{
  "entries": {
    "6681152659205225093" : {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    },
    "8350192447815228107" : {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    },
    "9408173275444922801" : {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    },
    "11244410301401252959" : {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    },
    "15346629759498347257" : {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    },
    "1228286566665971148" : {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    },
    "17471682139930361099" : {
      "status": "REVOKED",
      "reason": "SOFTWARE_FLAW"
    },
    "e80fcf7b85d652aa": {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    },
    "2621004353020741590": {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    },
    "1051246719628187981": {
      "status": "REVOKED",
      "reason": "KEY_COMPROMISE"
    }
  }
}
```




