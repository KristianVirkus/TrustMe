using System;
using System.Collections.Generic;

namespace TrustMe
{
    /// <summary>
    /// Common interface of all cryptographic keys.
    /// </summary>
    public interface IKey
    {
        /// <summary>
        /// Gets the key's hash including the cryptographic parameters,
        /// the embedded data (if any), and the signature.
        /// </summary>
        IHash Hash { get; }

        /// <summary>
        /// Gets the embedded data.
        /// </summary>
        IHashable EmbeddedData { get; }

        /// <summary>
        /// Gets the signature to prove this key's authentity.
        /// </summary>
        ISignature Signature { get; }

        /// <summary>
        /// Decrypts a cipher.
        /// </summary>
        /// <param name="cipher">The cipher.</param>
        /// <returns>The plain text.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///     <paramref name="cipher"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if
        ///     <paramref name="cipher"/> cannot be decrypted.</exception>
        byte[] Decrypt(IEnumerable<byte> cipher);

        /// <summary>
        /// Signs a hash value.
        /// </summary>
        /// <param name="hash">The hash.</param>
        /// <returns>The signature.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="hash"/> is null.</exception>
        ISignature Sign(IHash hash);

        /// <summary>
        /// Derives the matching unsigned certificate.
        /// </summary>
        /// <returns>The certificate.</returns>
        ICertificate DeriveCertificate();
    }

    /// <summary>
    /// Common interface of all cryptographic keys with embedded data.
    /// </summary>
    /// <typeparam name="TEmbeddedData">The type of the embedded data.</typeparam>
    public interface IKey<TEmbeddedData> : IKey where TEmbeddedData : IHashable
    {
        /// <summary>
        /// Gets the typed embedded data.
        /// </summary>
        TEmbeddedData EmbeddedDataTyped { get; }

        /// <summary>
        /// Derives the matching unsigned certificate.
        /// </summary>
        /// <returns>The certificate.</returns>
        new ICertificate<TEmbeddedData> DeriveCertificate();
    }
}
