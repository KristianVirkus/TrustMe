using FluentAssertions;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;

namespace TrustMe.UnitTests
{
	class RsaKeyTests
	{
		public class WithoutEmbeddedData
		{
			public class Constructors
			{
				[Test]
				public void Constructor_Should_SetProperties()
				{
					// Arrange
					// Act
					var obj = new RsaKey(parameters: Scenario.DefaultRsaParameters);

					// Assert
					var rsa = obj.CreateRsa();
					var rsaParameters = rsa.ExportParameters(true);
					rsaParameters.Modulus.SequenceEqual(Scenario.DefaultRsaParameters.Modulus).Should().BeTrue();
					rsaParameters.D.SequenceEqual(Scenario.DefaultRsaParameters.D).Should().BeTrue();
				}
			}

			public class Generation
			{
				[Test]
				public void GenerateWithoutSignature_Should_Succeed()
				{
					// Arrange
					// Act
					// Assert
					RsaKey.Generate().Should().NotBeNull();
				}

				[Test]
				public void GenerateAndSignCallback_Should_StoreSignature()
				{
					// Arrange
					var signature = new RsaSignature(Scenario.DefaultSignerCertificate.Hash, new byte[] { 0x11, 0x11, 0x11, 0x11 });

					// Act
					var key = RsaKey.Generate((_hash) => signature);

					// Assert
					key.Signature.Should().BeSameAs(signature);
				}

				[Test]
				public void GenerateAndSignCallbackWithExceptionInCallback_ShouldThrow_Exception()
				{
					// Arrange
					// Act & Assert
					Assert.Throws<NotImplementedException>(() => RsaKey.Generate((_hash) => throw new NotImplementedException()));
				}
			}

			public class SignAndVerify
			{
				[Test]
				public void SignHashNull_ShouldThrow_ArgumentNullException()
				{
					// Arrange
					var key = RsaKey.Generate();

					// Act & Assert
					Assert.Throws<ArgumentNullException>(() => key.Sign(hash: null));
				}

				[Test]
				public void SignCertificateNull_ShouldThrow_ArgumentNullException()
				{
					// Arrange
					var key = RsaKey.Generate();

					// Act & Assert
					Assert.Throws<ArgumentNullException>(() => key.Sign(certificate: null));
				}

				[Test]
				public void SignHashAndVerify_Should_Succeed()
				{
					// Arrange
					var key = RsaKey.Generate();
					var hash = Sha512Hash.Compute(new byte[] { 0x10, 0x20, 0x30, 0x40 });

					// Act
					var signature = key.Sign(hash: hash);

					// Assert
					signature.Should().BeOfType<RsaSignature>();
					key.DeriveCertificate().Verify(hash, signature);
				}

				[Test]
				public void SignCertificateAndVerify_Should_Succeed()
				{
					// Arrange
					var key = RsaKey.Generate();

					// Act
					var signedCertificate = key.Sign(certificate: Scenario.DefaultCertificate);

					// Assert
					signedCertificate.Should().BeOfType<RsaCertificate>();
					key.DeriveCertificate().Verify(signedCertificate.Hash, signedCertificate.Signature);
				}

				[Test]
				public void VerifySignatureForDifferentHash_ShouldThrow_TrustException()
				{
					// Arrange
					var key = RsaKey.Generate();
					var certificate = key.DeriveCertificate();
					var hashToSign = Sha512Hash.Compute(new byte[] { 0x1f, 0x2e, 0x3d, 0x4c });
					var otherHash = Sha512Hash.Compute(new byte[] { 0x01, 0x00, 0x03, 0x02 });

					// Act
					// Assert
					var signature = key.Sign(hashToSign);
					Assert.Throws<TrustException>(() => certificate.Verify(otherHash, signature));
				}

				[Test]
				public void VerifySignatureFromDifferentSigner_ShouldThrow_TrustException()
				{
					// Arrange
					var signerKey = RsaKey.Generate();
					var signerCertificate = signerKey.DeriveCertificate();
					var validatorKey = RsaKey.Generate();
					var validatorCertificate = signerKey.DeriveCertificate();
					var hashToSign = Sha512Hash.Compute(new byte[] { 0x1f, 0x2e, 0x3d, 0x4c });
					var otherHash = Sha512Hash.Compute(new byte[] { 0x01, 0x00, 0x03, 0x02 });

					// Act
					// Assert
					var signature = signerKey.Sign(hashToSign);
					Assert.Throws<TrustException>(() => validatorCertificate.Verify(otherHash, signature));
				}
			}

			public class CertificateDerivation
			{
				[Test]
				public void Derive_Should_CreateCertificateWithSameRsaExponentAndModulus()
				{
					// Arrange
					// Act
					var certificateRsaParameters = Scenario.DefaultKey.DeriveCertificate().CreateRsa().ExportParameters(false);

					// Assert
					certificateRsaParameters.Exponent.SequenceEqual(Scenario.DefaultRsaParameters.Exponent).Should().BeTrue();
					certificateRsaParameters.Modulus.SequenceEqual(Scenario.DefaultRsaParameters.Modulus).Should().BeTrue();
					// Certificates may not export private RSA cryptographic parameters.
					Assert.Throws(Is.InstanceOf<Exception>(), () => Scenario.DefaultKey.DeriveCertificate().CreateRsa().ExportParameters(true));
				}
			}
		}
	}
}
