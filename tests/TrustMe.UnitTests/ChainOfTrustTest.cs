using FluentAssertions;
using Moq;
using NUnit.Framework;
using System;
using System.Linq;

namespace TrustMe.UnitTests
{
	class ChainOfTrustTest
	{
		public class Constructors
		{
			[Test]
			public void TrustedCertificatesNull_ShouldThrow_ArgumentNullException()
			{
				// Arrange
				// Act & Assert
				Assert.Throws<ArgumentNullException>(() => new ChainOfTrust(trustedCertificates: (ICertificate[])null));
			}

			[Test]
			public void TrustedCertificatesEmpty_Should_Succeed()
			{
				// Arrange
				// Act & Assert
				var sut = new ChainOfTrust(trustedCertificates: new ICertificate[0]);
			}

			[Test]
			public void CertificateLocatorNull_ShouldThrow_ArgumentNullException()
			{
				// Arrange
				// Act & Assert
				Assert.Throws<ArgumentNullException>(() => new ChainOfTrust(
					certificateLocator: null,
					trustedCertificates: new ICertificate[0]));
			}
		}

		public class Verification
		{
			[Test]
			public void CertificateNull_ShouldThrow_ArgumentNullException()
			{
				// Arrange
				// Act & Assert
				Assert.Throws<ArgumentNullException>(() => Scenario.DefaultChain.Verify(null));
			}

			[Test]
			public void UnsignedCertificate_ShouldThrow_TrustException()
			{
				// Arrange
				var certificate = RsaKey.Generate().DeriveCertificate();

				// Act & Assert
				Assert.Throws<TrustException>(() => Scenario.DefaultChain.Verify(certificate));
			}

			[Test]
			public void CertificateSignedByTrustedSigner_Should_Succeed()
			{
				// Arrange
				var certificate = RsaKey.Generate().DeriveCertificate();
				var signedCertificate = Scenario.DefaultSignerKey.Sign((RsaCertificate)certificate);

				// Act
				// Assert
				Scenario.DefaultChain.Verify(signedCertificate);
			}

			[Test]
			public void CertificateSignedIndirectly_Should_FindIntermediateCertificateViaLocator()
			{
				// Arrange
				var intermediateKey = RsaKey.Generate();
				var intermediateCertificate = intermediateKey.DeriveCertificate();
				var signedIntermediateCertificate = Scenario.DefaultSignerKey.Sign((RsaCertificate)intermediateCertificate);
				var key = RsaKey.Generate();
				var certificate = key.DeriveCertificate();
				var signedCertificate = intermediateKey.Sign((RsaCertificate)certificate);

				var scenario = new Scenario3();
				var lookedUpIntermediateCertificate = false;
				Mock.Get(scenario.CertificateLocator)
					.Setup(m => m.Get(It.IsAny<IHash>()))
					.Returns<IHash>((_hash) =>
					{
						if (_hash.Hash.SequenceEqual(intermediateCertificate.Hash.Hash))
						{
							lookedUpIntermediateCertificate = true;
							return signedIntermediateCertificate;
						}
						else
						{
							return null;
						}
					});

				// Act
				// Assert
				scenario.ChainWithLocator.Verify(signedCertificate);
				lookedUpIntermediateCertificate.Should().BeTrue();
			}

			[Test]
			public void CertificateSignedWithUnlocatableCertificate_ShouldThrow_TrustException()
			{
				// Arrange
				var intermediateKey = RsaKey.Generate();
				var intermediateCertificate = intermediateKey.DeriveCertificate();
				var signedIntermediateCertificate = Scenario.DefaultSignerKey.Sign((RsaCertificate)intermediateCertificate);
				var key = RsaKey.Generate();
				var certificate = key.DeriveCertificate();
				var signedCertificate = intermediateKey.Sign((RsaCertificate)certificate);

				var scenario = new Scenario3();
				var lookedUpIntermediateCertificate = false;
				Mock.Get(scenario.CertificateLocator)
					.Setup(m => m.Get(It.IsAny<IHash>()))
					.Returns<IHash>((_hash) =>
					{
						lookedUpIntermediateCertificate = true;
						return null;
					});

				// Act
				// Assert
				Assert.Throws<TrustException>(() => scenario.ChainWithLocator.Verify(signedCertificate));
				lookedUpIntermediateCertificate.Should().BeTrue();
			}
		}
	}
}
