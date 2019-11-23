using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace TrustMe
{
    /// <summary>
    /// Common interface of all cryptographic certificates.
    /// </summary>
    public interface ICertificate
    {
        /// <summary>
        /// Gets the certificate's hash including the cryptographic parameters,
        /// the embedded data (if any).
        /// </summary>
        IHash Hash { get; }

        /// <summary>
        /// Gets the embedded data.
        /// </summary>
        IReadOnlyCollection<byte> EmbeddedData { get; }

        /// <summary>
        /// Gets the signature to prove this certificate's authenticity.
        /// </summary>
        ISignature Signature { get; }

        /// <summary>
        /// Gets the certificate's hash including the cryptographic parameters,
        /// the embedded data (if any), the signer's certificate's hash and
        /// signature (if signed.)
        /// </summary>
        IHash HashWithSignature { get; }

        /// <summary>
        /// Encrypts a <paramref name="plainText"/>.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <returns>The cipher.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="plainText"/> is null.</exception>
        ///	<exception cref="ArgumentOutOfRangeException">Thrown if
        ///	    <paramref name="plainText"/> is longer than allowed.</exception>
        byte[] Encrypt(IEnumerable<byte> plainText);

        /// <summary>
        /// Verifies the a <paramref name="hash"/> against this certificate.
        /// </summary>
        /// <param name="hash">The hash to verify.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="hash"/> or
        ///		<paramref name="signature"/> is null.</exception>
        ///	<exception cref="TrustException">Thrown if verification failed.</exception>
        void Verify(IHash hash, ISignature signature);

        /// <summary>
        /// Creates an instance of the <see cref="RSACryptoServiceProvider"/> class
        /// initialized with this instance's public RSA parameters.
        /// </summary>
        /// <returns>The RSA crypto provider instance.</returns>
        RSACryptoServiceProvider CreateRsa();
    }
}
