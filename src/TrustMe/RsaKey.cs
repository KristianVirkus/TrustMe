using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace TrustMe
{
    /// <summary>
    /// Implements an RSA cryptographic key.
    /// </summary>
    public class RsaKey : IKey
    {
        #region Constants

        /// <summary>
        /// Gets the RSA key size.
        /// </summary>
        public const int KeySize = 2048;

        #endregion

        #region Fields

        protected RSACryptoServiceProvider rsa;
        protected RSAParameters parameters;
        protected RsaSignature signature;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKey"/> class.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters.</param>
        public RsaKey(RSAParameters parameters)
        {
            this.parameters = parameters;
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: true,
                embeddedData: null);
            this.rsa = this.CreateRsa();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKey"/> class.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters.</param>
        /// <param name="embeddedData">The embedded data or null if none.</param>
        public RsaKey(RSAParameters parameters, IHashable embeddedData)
        {
            this.parameters = parameters;
            this.EmbeddedData = embeddedData;
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: true,
                embeddedData: embeddedData);
            this.rsa = this.CreateRsa();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKey"/> class.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters.</param>
        /// <param name="signature">The cryptographic RSA signature.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
        public RsaKey(RSAParameters parameters, RsaSignature signature)
        {
            this.parameters = parameters;
            this.signature = signature ?? throw new ArgumentNullException(nameof(signature));
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: true,
                embeddedData: null);
            this.rsa = this.CreateRsa();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKey"/> class.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters.</param>
        /// <param name="embeddedData">The embedded data or null if none.</param>
        /// <param name="signature">The cryptographic RSA signature.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
        public RsaKey(RSAParameters parameters, IHashable embeddedData, RsaSignature signature)
        {
            this.parameters = parameters;
            this.EmbeddedData = embeddedData;
            this.signature = signature ?? throw new ArgumentNullException(nameof(signature));
            this.Hash = Helpers.ComputeRsaHash(
                rsaParameters: parameters,
                includePrivateParameters: true,
                embeddedData: embeddedData);
            this.rsa = this.CreateRsa();
        }

        #endregion

        #region IKey implementation

        /// <summary>
        /// Gets the key's hash including the RSA parameters and the signature.
        /// </summary>
        public IHash Hash { get; }

        /// <summary>
        /// Gets the embedded data.
        /// </summary>
        public IHashable EmbeddedData { get; }

        /// <summary>
        /// Gets the signature to prove this key's authenticity.
        /// </summary>
        ISignature IKey.Signature => this.signature;

        /// <summary>
        /// Gets the RSA cryptographic signature to prove this key's authenticity.
        /// </summary>
        public RsaSignature Signature => this.signature;

        /// <summary>
        /// Creates an instance of the <see cref="RSACryptoServiceProvider"/> class
        /// initialized with this instance's public and private RSA parameters.
        /// </summary>
        /// <returns>The RSA crypto provider instance.</returns>
        public RSACryptoServiceProvider CreateRsa()
        {
            var rsa = new RSACryptoServiceProvider(KeySize);
            rsa.ImportParameters(this.parameters);
            return rsa;
        }

        /// <summary>
        /// Decrypts a cipher.
        /// </summary>
        /// <param name="cipher">The cipher.</param>
        /// <returns>The plain text.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///     <paramref name="cipher"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if
        ///     <paramref name="cipher"/> cannot be decrypted.</exception>
        public byte[] Decrypt(IEnumerable<byte> cipher)
        {
            if (cipher == null) throw new ArgumentNullException(nameof(cipher));
            if (cipher.Count() != RsaKey.KeySize / 8)
            {
                throw new ArgumentOutOfRangeException(
                    paramName: nameof(cipher),
                    message: "The cipher length is invalid.");
            }

            try
            {
                return this.rsa.Decrypt(cipher.ToArray(), RSAEncryptionPadding.Pkcs1);
            }
            catch (Exception ex)
            {
                throw new ArgumentException(
                    message: "Failed to decrypt cipher.",
                    innerException: ex);
            }
        }

        /// <summary>
        /// Signs a hash value.
        /// </summary>
        /// <param name="hash">The hash.</param>
        /// <returns>The signature.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="hash"/> is null.</exception>
        public ISignature Sign(IHash hash)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            return new RsaSignature(
                signerCertificateHash: this.DeriveCertificate().Hash,
                signature: this.rsa.SignHash(hash.Hash.ToArray(), hash.Name, RSASignaturePadding.Pkcs1));
        }

        /// <summary>
        /// Signs a certificate by its hash value.
        /// </summary>
        /// <param name="certificate">The certificate to sign.</param>
        /// <returns>The signed certificate.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="certificate"/> is null.</exception>
        public RsaCertificate Sign(RsaCertificate certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            // Create copy of RSA cryptographic parameters before creating the certificate
            // with these data to avoid manipulation of references of cryptographic parameters
            // via reflection or such.
            var rsaParameters = certificate.CreateRsa().ExportParameters(false);

            // Replace certificate by one with the same cryptographic RSA parameters
            // but no signature.
            var unsignedCertificate = new RsaCertificate(rsaParameters);
            var signature = new RsaSignature(
                signerCertificateHash: this.DeriveCertificate().Hash,
                signature: this.rsa.SignHash(
                    unsignedCertificate.Hash.Hash.ToArray(),
                    unsignedCertificate.Hash.Name,
                    RSASignaturePadding.Pkcs1));
            var signedCertificate = new RsaCertificate(rsaParameters, this.EmbeddedData, signature);
            return signedCertificate;
        }

        /// <summary>
        /// Derives the matching unsigned certificate.
        /// </summary>
        /// <returns>The certificate.</returns>
        public ICertificate DeriveCertificate()
        {
            // Create copy of RSA cryptographic parameters before creating the certificate
            // with these data to avoid manipulation of references of cryptographic parameters
            // via reflection or such.
            var rsaParameters = new RSAParameters
            {
                Exponent = this.parameters.Exponent.ToArray(),
                Modulus = this.parameters.Modulus.ToArray(),
            };
            return new RsaCertificate(rsaParameters, this.EmbeddedData);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Generates a new RSA key.
        /// </summary>
        /// <returns>The RSA key.</returns>
        public static RsaKey Generate()
        {
            var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
            var rsaParameters = rsa.ExportParameters(true);
            var key = new RsaKey(parameters: rsaParameters);
            return key;
        }

        /// <summary>
        /// Generates a new RSA key.
        /// </summary>
        /// <param name="embeddedData">The embedded data or null if none.</param>
        /// <returns>The RSA key.</returns>
        public static RsaKey Generate(IHashable embeddedData)
        {
            var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
            var rsaParameters = rsa.ExportParameters(true);
            var key = new RsaKey(parameters: rsaParameters, embeddedData: embeddedData);
            return key;
        }

        /// <summary>
        /// Generates a new signed RSA key.
        /// </summary>
        /// <param name="signKeyCallback">The callback method to invoke for signing the key.</param>
        /// <returns>The RSA key.</returns>
        public static RsaKey Generate(Func<IHash, RsaSignature> signKeyCallback)
        {
            if (signKeyCallback == null)
                throw new ArgumentNullException(nameof(signKeyCallback));
            var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
            var rsaParameters = rsa.ExportParameters(true);
            var key = new RsaKey(parameters: rsaParameters);
            var signature = signKeyCallback?.Invoke(
                    Helpers.ComputeRsaHash(
                        rsaParameters: rsaParameters,
                        includePrivateParameters: true,
                        embeddedData: null));
            key = new RsaKey(
                parameters: rsaParameters,
                signature: signature);
            return key;
        }

        /// <summary>
        /// Generates a new signed RSA key.
        /// </summary>
        /// <param name="embeddedData">The embedded data or null if none.</param>
        /// <param name="signKeyCallback">The callback method to invoke for signing the key.</param>
        /// <returns>The RSA key.</returns>
        public static RsaKey Generate(IHashable embeddedData, Func<IHash, RsaSignature> signKeyCallback)
        {
            if (signKeyCallback == null)
                throw new ArgumentNullException(nameof(signKeyCallback));
            var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
            var rsaParameters = rsa.ExportParameters(true);
            var key = new RsaKey(parameters: rsaParameters, embeddedData: embeddedData);
            var signature = signKeyCallback?.Invoke(
                    Helpers.ComputeRsaHash(
                        rsaParameters: rsaParameters,
                        includePrivateParameters: true,
                        embeddedData: embeddedData));
            key = new RsaKey(
                parameters: rsaParameters,
                embeddedData: embeddedData,
                signature: signature);
            return key;
        }

        #endregion
    }

    public class RsaKey<TEmbeddedData> : RsaKey, IKey<TEmbeddedData> where TEmbeddedData : IHashable
    {
        #region Properties

        /// <summary>
        /// Gets the embedded data.
        /// </summary>
        public TEmbeddedData EmbeddedDataTyped { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKey"/> class.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters.</param>
        /// <param name="embeddedData">The embedded data or null if none.</param>
        public RsaKey(RSAParameters parameters, TEmbeddedData embeddedData)
            : base(parameters: parameters, embeddedData: embeddedData)
        {
            this.EmbeddedDataTyped = embeddedData;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKey"/> class.
        /// </summary>
        /// <param name="parameters">The cryptographic RSA parameters.</param>
        /// <param name="embeddedData">The embedded data or null if none.</param>
        /// <param name="signature">The cryptographic RSA signature.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
        public RsaKey(RSAParameters parameters, TEmbeddedData embeddedData, RsaSignature signature)
            : this(parameters: parameters, embeddedData: embeddedData)
        {
            this.signature = signature ?? throw new ArgumentNullException(nameof(signature));
        }

        #endregion

        #region Methods

        /// <summary>
        /// Generates a new RSA key pair with embedded data.
        /// </summary>
        /// <param name="embeddedData">The embedded data. These will be included in the
        ///		keys hash and thus when it gets signed.</param>
        /// <returns>The RSA key.</returns>
        public static RsaKey<TEmbeddedData> Generate(TEmbeddedData embeddedData)
        {
            var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
            var rsaParameters = rsa.ExportParameters(true);
            var key = new RsaKey<TEmbeddedData>(parameters: rsaParameters, embeddedData: embeddedData);
            return key;
        }

        /// <summary>
        /// Generates a new signed RSA key.
        /// </summary>
        /// <param name="embeddedData">The embedded data or null if none.</param>
        /// <param name="signKeyCallback">The callback method to invoke for signing the key.</param>
        /// <returns>The RSA key.</returns>
        public static RsaKey Generate(TEmbeddedData embeddedData, Func<IHash, RsaSignature> signKeyCallback)
        {
            if (signKeyCallback == null)
                throw new ArgumentNullException(nameof(signKeyCallback));
            var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
            var rsaParameters = rsa.ExportParameters(true);
            var key = new RsaKey<TEmbeddedData>(parameters: rsaParameters, embeddedData: embeddedData);
            var signature = signKeyCallback?.Invoke(
                    Helpers.ComputeRsaHash(
                        rsaParameters: rsaParameters,
                        includePrivateParameters: true,
                        embeddedData: embeddedData));
            key = new RsaKey<TEmbeddedData>(
                parameters: rsaParameters,
                embeddedData: embeddedData,
                signature: signature);
            return key;
        }

        /// <summary>
        /// Derives the matching unsigned certificate.
        /// </summary>
        /// <returns>The certificate.</returns>
        new public ICertificate<TEmbeddedData> DeriveCertificate()
        {
            // Create copy of RSA cryptographic parameters before creating the certificate
            // with these data to avoid manipulation of references of cryptographic parameters
            // via reflection or such.
            var rsaParameters = new RSAParameters
            {
                Exponent = this.parameters.Exponent.ToArray(),
                Modulus = this.parameters.Modulus.ToArray(),
            };
            return new RsaCertificate<TEmbeddedData>(rsaParameters, this.EmbeddedDataTyped);
        }

        #endregion
    }
}
