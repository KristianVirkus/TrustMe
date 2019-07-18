using System.Collections.ObjectModel;

namespace TrustMe
{
	/// <summary>
	/// Common interface of all signatures.
	/// </summary>
	public interface ISignature
	{
		/// <summary>
		/// Gets the hash of the signature including the signer's certificate's hash
		/// and the signature data.
		/// </summary>
		IHash Hash { get; }

		/// <summary>
		/// Gets the signer's certificate's hash.
		/// </summary>
		IHash SignerCertificateHash { get; }

		/// <summary>
		/// Gets the signature data.
		/// </summary>
		ReadOnlyCollection<byte> Signature { get; }
	}
}
