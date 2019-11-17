using System;
using System.Collections.Generic;
using System.Linq;

namespace TrustMe
{
	/// <summary>
	/// Implements a chain of trust, directly trusting some certificates
	/// and looking others up via a certificate locator.
	/// </summary>
	public class ChainOfTrust : IChainOfTrust
	{
		#region Fields

		private readonly ICertificateLocator certificateLocator;
		private readonly IEnumerable<ICertificate> trustedCertificates;

		#endregion

		#region Constructors

		/// <summary>
		/// Initializes a new instance of the <see cref="ChainOfTrust"/> class.
		/// </summary>
		/// <param name="trustedCertificates">The trusted certificates to successfully
		///		terminate validation at.</param>
		public ChainOfTrust(params ICertificate[] trustedCertificates)
		{
			this.trustedCertificates = trustedCertificates ?? throw new System.ArgumentNullException(nameof(trustedCertificates));
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="ChainOfTrust"/> class.
		/// </summary>
		/// <param name="trustedCertificates">The trusted certificates to successfully
		///		terminate validation at.</param>
		/// <param name="certificateLocator">The locator for mentioned untrusted certificates.</param>
		public ChainOfTrust(ICertificateLocator certificateLocator,
			params ICertificate[] trustedCertificates)
			: this(trustedCertificates)
		{
			this.certificateLocator = certificateLocator ?? throw new System.ArgumentNullException(nameof(certificateLocator));
		}

		#endregion

		#region IChainOfTrust implementation

		/// <summary>
		/// Verifies a <param name="certificate"/> against its signer's certificate
		/// and further up to a known and trusted certificate.
		/// </summary>
		/// <exception cref="ArgumentNullException">Thrown if
		///		<paramref name="certificate"/> is null.</exception>
		///	<exception cref="TrustException">Thrown if the certificate is either
		///		not signed or the signature is untrusted.</exception>
		public void Verify(ICertificate certificate)
		{
			if (certificate == null) throw new ArgumentNullException(nameof(certificate));

			IHash certificateSignerHash = certificate.Signature?.SignerCertificateHash;
			while (certificateSignerHash != null)
			{
				// First check signature amongst trusted/known certificates.
				var signerCertificatesTrusted = from c in this.trustedCertificates
												where c.Hash.Equals(certificateSignerHash)
												select c;
				if (signerCertificatesTrusted.Count() > 1)
					throw new TrustException("Ambiguous signer certificate.");

				// Check signature against trusted/known signer, if any.
				var signerCertificateTrusted = signerCertificatesTrusted.SingleOrDefault();
				if (signerCertificateTrusted != null)
				{
					signerCertificateTrusted.Verify(certificate.Hash, certificate.Signature);
					return;
				}

				// No matching trusted certificate found, locate signer's certificate.
				if (this.certificateLocator == null) throw new TrustException("Integrity of the certificate cannot be verified due to untrusted certificate in the chain of trust.");
				var signerCertificate = this.certificateLocator.Get(certificateSignerHash);
				if (signerCertificate == null)
					throw new TrustException("The certificate's signer certificate could not be found.");

				// Check the certificates integrity against its located signer's certificate.
				signerCertificate.Verify(certificate.Hash, certificate.Signature);

				// Continue up to the root of the signature chain.
				certificate = signerCertificate;
				certificateSignerHash = certificate.Signature?.SignerCertificateHash;
			}

			throw new TrustException("The certificate is either unsigned or the signature is untrusted.");
		}

		#endregion
	}
}