using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Linq;

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
		/// <param name="signature">The cryptographic RSA signature.</param>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
		public RsaKey(RSAParameters parameters, RsaSignature signature)
		{
			if (signature == null) throw new ArgumentNullException(nameof(signature));

			this.parameters = parameters;
			this.Signature = signature;
			this.Hash = Helpers.ComputeRsaHash(
				rsaParameters: parameters,
				includePrivateParameters: true,
				embeddedData: null);
			this.rsa = this.CreateRsa();
		}

		#endregion

		#region IKey implementation

		/// <summary>
		/// Gets the key's hash including the RSA parameters and the signature.
		/// </summary>
		public IHash Hash { get; }

		/// <summary>
		/// Gets the signature to prove this key's authenticity.
		/// </summary>
		ISignature IKey.Signature => this.Signature;

		/// <summary>
		/// Gets the RSA cryptographic signature to prove this key's authenticity.
		/// </summary>
		public RsaSignature Signature { get; }

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

		public ReadOnlyCollection<byte> Decrypt(ReadOnlyCollection<byte> cipher)
		{
			throw new NotImplementedException();
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
			var signedCertificate = new RsaCertificate(rsaParameters, signature);
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
			return new RsaCertificate(rsaParameters);
		}

		#endregion

		#region Methods

		public static RsaKey Generate()
		{
			var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
			var rsaParameters = rsa.ExportParameters(true);
			var key = new RsaKey(parameters: rsaParameters);
			return key;
		}

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

		#endregion
	}

	public class RsaKey<TEmbeddedData> : RsaKey, ICertificate<TEmbeddedData> where TEmbeddedData : IHashable
	{
		#region Constructors

		/// <summary>
		/// Initializes a new instance of the <see cref="RsaKey"/> class.
		/// </summary>
		/// <param name="parameters">The cryptographic RSA parameters.</param>
		/// <param name="signature">The cryptographic RSA signature.</param>
		/// <param name="embeddedData">The embedded data.</param>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="signature"/> is null.</exception>
		public RsaKey(RSAParameters parameters, RsaSignature signature, TEmbeddedData embeddedData)
			: base(parameters: parameters, signature: signature)
		{
			this.EmbeddedData = embeddedData;
			if (this.EmbeddedData != null)
				this.Hash = Helpers.ComputeRsaHash(
					rsaParameters: this.parameters,
					includePrivateParameters: true,
					embeddedData: this.EmbeddedData);
		}

		#endregion

		#region IKey<TEmbeddedData> implementation

		public TEmbeddedData EmbeddedData { get; }

		/// <summary>
		/// Gets the key's hash including the RSA parameters,
		/// the embedded data (if any), and the signature.
		/// </summary>
		new public IHash Hash { get; }

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
			throw new NotImplementedException();
		}

		#endregion
	}
}
