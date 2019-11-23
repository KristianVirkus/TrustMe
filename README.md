# Trust Me

This library is about trust. It implements a public key/private key handling solution for RSA 2048 bits and SHA512 operations with validation chain.

Using these functions, one can build an own PKI (Public Key Infrastructure). However the keys and certificates do not comply with any web standards by design. Therefore they are not suitable for use with web servers or e-mail though the principles of asymmetric cryptography are the same. The intention for this library was to create a custom solution to apply the PKI principles to non-web tasks.

The implemented functions are:

* Create RSA keys and derive certificates [usage](USAGE.md#keys-and-certificates)
* Embed arbitrary data in keys and certificates [usage](USAGE.md#embed-data)
* Hash arbitrary byte data [usage](USAGE.md#hashing)
* Sign hashes [usage](USAGE.md#sign-and-verify)
* Verify signature against original hash [usage](USAGE.md#sign-and-verify)
* Asymmetrically encrypt and decrypt data [usage](USAGE.md#encrypt-and-decrypt)
* Verify chains of signed certificates [usage](USAGE.md#chain-of-trust)
* Serializing and deserializing keys and certificates to/from streams [usage](USAGE.md#serialization-and-deserialization)

**If you update to version 1.1 there's a breaking change: The keys and certificates no longer have generic versions of their interfaces and classes. This is because the hashable embedded data objects (which the generic type was for) have been replaced by arbitrary byte streams to allow for easy (de-)serialization.**

## Installation

This library can either be compiled oneself or retrieved via NuGet. The package name is `TrustMe`. The NuGet package contains the signed version of the library while for manual compilation the signing must be disabled or one must use their own key.

## Usage

Please refer to the documentation located [here](USAGE.md).

There is also a sample application available in this repository.

## Known Issues and Vulnerabilities

None, yet. Please feel free to raise an issue, create a pull request or contact me directly.

## License

This library is licensed under the MIT license. See [LICENSE](LICENSE). This effectively means that you may use or modify it for any purpose as long as you mention the original author.

This library uses code from the .NET Foundation and its contributors for generating C# object hash codes. Please see [link](src/TrustMe/HashCode/Computer.cs) for details.
