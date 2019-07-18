using System;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

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
		/// Gets the signature to prove this key's authentity.
		/// </summary>
		ISignature Signature { get; }

		/// <summary>
		/// Decrypts a cipher.
		/// </summary>
		/// <param name="cipher">The cipher.</param>
		/// <returns>The plain text.</returns>
		ReadOnlyCollection<byte> Decrypt(ReadOnlyCollection<byte> cipher);

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
	//public interface IKey<TEmbeddedData> : IKey, ICertificate<TEmbeddedData> where TEmbeddedData : IHashable
	//{
	//}
}
