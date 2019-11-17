using System;

namespace TrustMe
{
	/// <summary>
	/// Common interface of all chains of trust.
	/// </summary>
	public interface IChainOfTrust
	{
		/// <summary>
		/// Verifies a <param name="certificate"/> against its signer's certificate
		/// and further up to a known and trusted certificate.
		/// </summary>
		/// <exception cref="ArgumentNullException">Thrown if
		///		<paramref name="certificate"/> is null.</exception>
		///	<exception cref="TrustException">Thrown if the certificate is either
		///		not signed or the signature is untrusted.</exception>
		void Verify(ICertificate certificate);
	}
}
