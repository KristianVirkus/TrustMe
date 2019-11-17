# Trust Me Usage

This library is about trust. It implements a public key/private key handling solution for RSA 2048 bits and SHA512 operations with validation chain.

Using these functions, one can build an own PKI (Public Key Infrastructure). However the keys and certificates do not comply with any web standards by design. Therefore they are not suitable for use with web servers or e-mail though the principles of asymmetric cryptography are the same. The intention for this library was to create a custom solution to apply the PKI principles to non-web tasks.

This document will give a hint on how to use the library.

## Keys and Certificates

Public key cryptography is based on public keys and private keys, managed as "certificates" (public key information only) and "keys" (private key information). This library can import keys and certificates from .NET `RSAParameters` for further usage. Persisting these data is up to the developer. The certificate (which is a subset of a key) can also be derived from a key.

1. Create RSA certificate from `RSAParameters`

```csharp
var rsaParameters = new RSAParameters() { D = ... };
var certificate = new RsaCertificate(rsaParameters);
```

2. Create RSA key from `RSAParameters`

```csharp
var rsaParameters = new RSAParameters() { D = ... };
var key = new RsaKey(rsaParameters);
```

3. Derive RSA certificate from key

```csharp
var rsaParameters = new RSAParameters() { D = ... };
var key = new RsaKey(rsaParameters);
var certificate = key.DeriveCertificate();
```

4. Generate a new key and its certificate:

```csharp
var key = RsaKey.Generate();
var certificate = key.DeriveCertificate();
```

Any certificate and key does own an SHA512 hash value over all public cryptographic parameters thus representing it uniquely. Private key cryptographic parameters are never considered. Thus, a key's and its derived certificate's hash value are the same.

## Embed data

Certificates and keys may also include arbitrary data which are then part of the certificate or key and considered in the hash value. When a certificate is derived from a key, it will also include the embedded data. The embedded data must implement `IHashable` such that it can easily be considered in calculating the key's and certificate's hash value.

1. Create key with embedded data:

```csharp
var rsaParameters = new RSAParameters() { D = ... };
var hashableData = new HashableString("test");
var key = new RsaKey(rsaParameters, hashableData);
```

2. Create certificate with embedded data:
```csharp
var rsaParameters = new RSAParameters() { D = ... };
var hashableData = new HashableString("test");
var certificate = new RsaCertificate(rsaParameters, hashableData);
```

3. Generate key with embedded data:

```csharp
var hashableData = new HashableString("test");
var key = RsaKey.Generate(hashableData);
```

To work with embedded data, the classes `HashableString` and `HashableByteArray` are included to quickly implement simple requirements.

The embedded data itself is accessible through the property `EmbeddedData`. If the generic versions of `RsaKey<TEmbeddedData>` and `RsaCertificate<TEmbeddedData>` are used, there is also a property `EmbeddedDataTyped` which references the same object.

## Hashing

To unify hashing there exists an interface `IHash` which represents a hash value. The included `Sha512Hash` leverages the SHA512 hash algorithm using the .NET implementation `SHA512Managed`.

To compute a hash value of any byte data use the static method `Compute`:

```csharp
byte[] data = ...;
var hash = Sha512Hash.Compute(data);
```

The interface `IHash` derives from the `IEquatable<IHash>` interface such that two instances can be compared using the `Equals` method.

## Sign and Verify

Finally leveraging the unique properties of asymmetric cryptography, arbitrary data can be signed using a (private) key and then be verified using a certificate (public key). However the data to be signed must be a hash value or a certificate (finally also working on its hash value). Signing a certificate does not affect it's hash value, it only adds the signers certificate hash and the signature. Optional embedded data is included in the signature as it is also included in the hash value.

1. Sign a certificate:

```csharp
var rootKey = new RsaKey(...);
var certificate = new RsaCertificate(...);
var signedCertificate = rootKey.Sign(certificate);
rootKey.DeriveCertificate().Verify(signedCertificate.Hash, signedCertificate.Signature);
```

The `Verify` method will throw a `TrustException` if the signature is invalid.

2. Sign a hash value:

```csharp
var key = new RsaKey(...);
byte[] data = ...;
var hash = Sha512Hash.Compute(data);
var signature = key.Sign(hash);
key.DeriveCertificate().Verify(hash, signature);
```

To sign arbitrary data, create a hash value over it and sign that hash value.

For PKI functionality a certificate should be signed and then the signed certificate can be distributed. As this implementation is somewhat made for specific non-web purposes, it's up to the developer to manage any PKI root certificates, registries, revocation lists and such.

## Encrypt and Decrypt

Asymmetric cryptography can, aside from signing and verifying hashes, also be used for encrypting and decrypting arbitrary data. However the amount of data is restricted by the used algorithm. This library uses RSA with 2048 bits, thus the amount of data is restricted to 245 bytes but may be shorter. If more data is to be encrypted, it is common to encrypt the data itself using a symmetric cryptography algorithm (e. g. AES256) and only encrypting the passphrase asymmetrically. Then the encrypted passphrase is distributed along with the symmetrically encrypted data. Due to the principles of asymmetric cryptography, encryption is done via the certificate (public key) while the decrypting is done via the (private) key:

```csharp
var key = RsaKey.Generate();
var certificate = key.DeriveCertificate();
var plainText = "test data";
var cipher = certificate.Encrypt(Encoding.UTF8.GetBytes(plainText));
plainText = Encoding.UTF8.GetString(key.Decrypt(cipher));
```

## Chain of Trust

The chain of trust actually helps implementing a PKI and thus allows to verify the signature of a certificate against a set of well-known root certificates. Any certificates used for signing a certificate on the way up to a well-known root certificate will be requested via a certificate look-up callback method. As this implementation is somewhat made for specific non-web purposes, it's up to the developer to manage any PKI root certificates, registries, revocation lists and such.

```csharp
ICertificate rootCertificate;
ICertificate intermediateCertificate;
ICertificate clientCertificate;

void test()
{
    // Preparation. Create keys and sign certificates.
    var rootKey = RsaKey.Generate();
    rootCertificate = rootKey.DeriveCertificate();
    var intermediateKey = RsaKey.Generate();
    intermediateCertificate = rootKey.Sign((RsaCertificate)intermediateKey.DeriveCertificate());
    var clientKey = RsaKey.Generate();
    clientCertificate = intermediateKey.Sign((RsaCertificate)clientKey.DeriveCertificate());

    // Verification.
    var certificateLocator = new Locator();
    var chainOfTrust = new ChainOfTrust(certificateLocator, rootCertificate);
    chainOfTrust.Verify(clientCertificate);
}

class Locator : ICertificateLocator
{
    public ICertificate Get(IHash hash)
    {
        // TODO Load certificates from a certificate store.
        if (hash.Equals(intermediateCertificate.Hash)) return intermediateCertificate;
        if (hash.Equals(clientCertificate.Hash)) return clientCertificate;
        throw new TrustException("Could not find certificate.");
    }
}
```

Pay attention that the client certificate is not directly signed by the root certificate and the intermediate certificate is not directly set-up as trusted certificate in the chain of trust but rather looked up and verified itself.
