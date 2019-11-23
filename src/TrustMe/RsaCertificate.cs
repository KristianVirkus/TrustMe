using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace TrustMe
{
    /// <summary>
    /// Implements a RSA certificate.
    /// </summary>
    public class RsaCertificate : ICertificate
    {
        #region Fields

        private readonly RSAParameters parameters;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the embedded data.
        /// </summary>
        public IReadOnlyCollection<byte> EmbeddedData { get; }

        /// <summary>
        /// Gets the RSA signature.
        /// </summary>
        public RsaSignature Signature { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCertificate"/> class
        /// for an unsigned RSA certificate.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters. Be sure not to
        ///		include any private parameters.</param>
        public RsaCertificate(RSAParameters parameters)
        {
            this.parameters = parameters;
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: null);
            this.HashWithSignature = Helpers.ComputeRsaHashWithSignature(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: null,
                signature: null);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCertificate"/> class
        /// for an unsigned RSA certificate.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters. Be sure not to
        ///		include any private parameters.</param>
        ///	<param name="embeddedData">The embedded data or null if none.</param>
        public RsaCertificate(RSAParameters parameters, IEnumerable<byte> embeddedData)
        {
            this.parameters = parameters;
            this.EmbeddedData = embeddedData?.ToArray();
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: embeddedData);
            this.HashWithSignature = Helpers.ComputeRsaHashWithSignature(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: embeddedData,
                signature: null);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCertificate"/> class
        /// for a signed certificate. This constructor is intended to be used
        /// when loading an existing certificate from a file or the like.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters. Be sure not to
        ///		include any private parameters.</param>
        /// <param name="signature">The RSA signature.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
        public RsaCertificate(RSAParameters parameters, RsaSignature signature)
        {
            this.parameters = parameters;
            this.Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: null);
            this.HashWithSignature = Helpers.ComputeRsaHashWithSignature(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: null,
                signature: this.Signature);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCertificate"/> class
        /// for a signed certificate. This constructor is intended to be used
        /// when loading an existing certificate from a file or the like.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters. Be sure not to
        ///		include any private parameters.</param>
        ///	<param name="embeddedData">The embedded data or null if none.</param>
        /// <param name="signature">The RSA signature.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
        public RsaCertificate(RSAParameters parameters, IEnumerable<byte> embeddedData,
            RsaSignature signature)
        {
            this.parameters = parameters;
            this.EmbeddedData = embeddedData?.ToArray();
            this.Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: embeddedData);
            this.HashWithSignature = Helpers.ComputeRsaHashWithSignature(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: embeddedData,
                signature: this.Signature);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCertificate"/> class
        /// for a signed certificate. This constructor is intended to be used
        /// when creating a new certificate from within an application.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters. Be sure not to
        ///		include any private parameters.</param>
        /// <param name="signCertificateCallback">The callback method to be invoked after
        ///		the hash value was calculated from the cryptographic RSA parameters in order
        ///		to get the signature determined from that hash value.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
        public RsaCertificate(RSAParameters parameters, Func<IHash, RsaSignature> signCertificateCallback)
        {
            if (signCertificateCallback == null) throw new ArgumentNullException(nameof(signCertificateCallback));

            this.parameters = parameters;

            // Compute preliminary hash which does not include a signature.
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: null);
            this.Signature = signCertificateCallback.Invoke(this.Hash);

            // Re-compute hash which now includes the signature.
            this.HashWithSignature = Helpers.ComputeRsaHashWithSignature(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: null,
                signature: this.Signature);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCertificate"/> class
        /// for a signed certificate. This constructor is intended to be used
        /// when creating a new certificate from within an application.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters. Be sure not to
        ///		include any private parameters.</param>
        ///	<param name="embeddedData">The embedded data or null if none.</param>
        /// <param name="signCertificateCallback">The callback method to be invoked after
        ///		the hash value was calculated from the cryptographic RSA parameters in order
        ///		to get the signature determined from that hash value.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
        public RsaCertificate(RSAParameters parameters, IEnumerable<byte> embeddedData,
            Func<IHash, RsaSignature> signCertificateCallback)
        {
            if (signCertificateCallback == null) throw new ArgumentNullException(nameof(signCertificateCallback));

            this.parameters = parameters;
            this.EmbeddedData = embeddedData?.ToArray();

            // Compute preliminary hash which does not include a signature.
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: embeddedData);
            this.Signature = signCertificateCallback.Invoke(this.Hash);

            // Re-compute hash which now includes the signature.
            this.HashWithSignature = Helpers.ComputeRsaHashWithSignature(
                rsaParameters: parameters,
                includePrivateParameters: false,
                embeddedData: embeddedData,
                signature: this.Signature);
        }

        #endregion

        #region ICertificate implementation

        /// <summary>
        /// Gets the certificate's hash including the RSA parameters,
        /// the embedded data (if any), and the signer's certificate's
        /// hash if signed.
        /// </summary>
        public IHash Hash { get; }

        /// <summary>
        /// Gets the signature to prove this certificate's authenticity.
        /// </summary>
        ISignature ICertificate.Signature => this.Signature;

        /// <summary>
        /// Gets the certificate's hash including the cryptographic parameters,
        /// the embedded data (if any), the signer's certificate's hash and
        /// signature (if signed.)
        /// </summary>
        public IHash HashWithSignature { get; }

        /// <summary>
        /// Encrypts a <paramref name="plainText"/>.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <returns>The cipher.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="plainText"/> is null.</exception>
        ///	<exception cref="ArgumentOutOfRangeException">Thrown if
        ///	    <paramref name="plainText"/> is longer than allowed.</exception>
        public byte[] Encrypt(IEnumerable<byte> plainText)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));
            if (plainText.Count() > this.GetMaximumPlainTextLengthForEncryption())
            {
                throw new ArgumentOutOfRangeException(
                    paramName: nameof(plainText),
                    message: "The plain text is too long.");
            }

            return this.CreateRsa().Encrypt(plainText.ToArray(), RSAEncryptionPadding.Pkcs1);
        }

        /// <summary>
        /// Gets the maximum allowed plain text length for encryption.
        /// </summary>
        /// <remarks>Formula taken at 2019-11-16 from: https://stackoverflow.com/a/3253142</remarks>
        /// <returns>The maximum allowed length.</returns>
        public int GetMaximumPlainTextLengthForEncryption() => ((RsaKey.KeySize - 384) / 8) + 37;

        /// <summary>
        /// Verifies the a <paramref name="hash"/> against this certificate.
        /// </summary>
        /// <param name="hash">The hash to verify.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="hash"/> or <paramref name="signature"/> is null.</exception>
        ///	<exception cref="TrustException">Thrown if verification failed.</exception>
        public void Verify(IHash hash, ISignature signature)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (!(signature is RsaSignature rsaSignature)) throw new TrustException("Incompatible signature.");
            if (!signature.SignerCertificateHash.Hash.SequenceEqual(this.Hash.Hash))
                throw new TrustException("The signature had been issued with a different key.");

            using (var rsa = this.CreateRsa())
            {
                if (!rsa.VerifyHash(hash.Hash.ToArray(), signature.Signature.ToArray(),
                    hash.Name, RSASignaturePadding.Pkcs1))
                    throw new TrustException("Failed to verify signature.");
            }
        }

        /// <summary>
        /// Creates an instance of the <see cref="RSACryptoServiceProvider"/> class
        /// initialized with this instance's public RSA parameters.
        /// </summary>
        /// <returns>The RSA crypto provider instance.</returns>
        public RSACryptoServiceProvider CreateRsa()
        {
            var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
            rsa.ImportParameters(this.parameters);
            return rsa;
        }

        #endregion

        #region Public methods

        public override bool Equals(object obj)
            => this.HashWithSignature?.Hash.SequenceEqual((obj as RsaCertificate)?.HashWithSignature.Hash) ?? false;

        public override int GetHashCode()
            => this.HashWithSignature.GetHashCode();

        #endregion
    }
}
