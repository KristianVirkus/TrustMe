using FluentAssertions;
using NUnit.Framework;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TrustMe.UnitTests
{
	class RsaCertificateTest
	{
		static RsaCertificate createWithoutSignature(
			RSAParameters? parameters = null)
		=> new RsaCertificate(
				parameters: parameters ?? Scenario.DefaultRsaParameters);

		static RsaCertificate createWithSignature(
			RSAParameters? parameters = null,
			RsaSignature signature = null, bool makeSignatureNull = false)
		=> new RsaCertificate(
				parameters: parameters ?? Scenario.DefaultRsaParameters,
				signature: signature ?? (makeSignatureNull ? null : Scenario.DefaultSignature));

		static RsaCertificate createWithSignatureCallback(
			RSAParameters? parameters = null,
			Func<IHash, RsaSignature> signCertificateCallback = null, bool makeSignCertificateCallbackNull = false)
		=> new RsaCertificate(
				parameters: parameters ?? Scenario.DefaultRsaParameters,
				signCertificateCallback: signCertificateCallback ?? (makeSignCertificateCallbackNull ? (Func<IHash, RsaSignature>)null : (_hash) => createRsaSignature()));

		static RsaSignature createRsaSignature(
			IHash signerCertificateHash = null, bool makeSignerCertificateHashNull = false,
			byte[] signature = null, bool makeSignatureNull = false)
		=> new RsaSignature(
			signerCertificateHash: signerCertificateHash ?? (makeSignerCertificateHashNull ? null : Scenario.DefaultSignerCertificateHash),
			signature: signature ?? (makeSignatureNull ? null : Scenario.DefaultSignatureData));

		public class WithoutSignature
		{
			public class ConstructorsWithSignatureCallback
			{
				[Test]
				public void Constructor_Should_SetProperties()
				{
					// Arrange
					// Act
					var obj = new RsaCertificate(parameters: Scenario.DefaultRsaParameters);
					var rsa = obj.CreateRsa();
					var rsaParameters = rsa.ExportParameters(false);

					// Assert
					rsaParameters.Exponent.SequenceEqual(Scenario.DefaultRsaParameters.Exponent).Should().BeTrue();
					rsaParameters.Modulus.SequenceEqual(Scenario.DefaultRsaParameters.Modulus).Should().BeTrue();
				}
			}

			public class Hashing
			{
				[Test]
				public void HashFromSameCertificateParameters_Should_ComputeSameHashes()
				{
					// Arrange
					var certificate1 = createWithoutSignature();
					var certificate2 = createWithoutSignature();

					// Act
					// Assert
					certificate1.Hash.Hash.SequenceEqual(certificate2.Hash.Hash).Should().BeTrue();
				}

				[Test]
				public void HashFromDifferentCertificateParameters_Should_ComputeDifferentHashes()
				{
					// Arrange
					var certificate1 = createWithoutSignature();
					var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
					var rsaParameters = rsa.ExportParameters(false);
					var certificate2 = createWithoutSignature(parameters: rsaParameters);

					// Act
					// Assert
					certificate1.Hash.Equals(certificate2.Hash).Should().BeFalse();
				}
			}

			public class Equality
			{
				[Test]
				public void SameParameters_ShouldReturn_True()
				{
					// Arrange
					var certificate1 = new RsaCertificate(parameters: Scenario1.RsaParameters);
					var certificate2 = new RsaCertificate(parameters: Scenario1.RsaParameters);

					// Act
					// Assert
					certificate1.Equals(certificate2).Should().BeTrue();
				}

				[Test]
				public void DifferentParameters_ShouldReturn_False()
				{
					// Arrange
					var certificate1 = new RsaCertificate(parameters: Scenario1.RsaParameters);
					var certificate2 = new RsaCertificate(parameters: Scenario2.RsaParameters);

					// Act
					// Assert
					certificate1.Equals(certificate2).Should().BeFalse();
				}
			}

			public class GetHashCodeMethod
			{
				[Test]
				public void GetHashCode_ShouldReturn_HashCodeOfHashWithSignatureProperty()
				{
					// Arrange
					var rsa = new RsaCertificate(Scenario1.RsaParameters);

					// Act
					// Assert
					rsa.GetHashCode().Should().Be(rsa.HashWithSignature.GetHashCode());
				}
			}
		}

		public class WithSignature
		{
			public class ConstructorsWithSignatureCallback
			{
				[Test]
				public void SignatureCallbackNull_ShouldThrow_ArgumentNullException()
				{
					// Arrange
					// Act & Assert
					Assert.Throws<ArgumentNullException>(() => createWithSignatureCallback(makeSignCertificateCallbackNull: true));
				}

				[Test]
				public void SignatureCallbackWithCorrectDataHash_Should_SetProperties()
				{
					// Arrange
					var signature = createRsaSignature();

					// Act
					var obj = createWithSignatureCallback(signCertificateCallback: (_hash) => signature);

					// Assert
					obj.Signature.Should().BeSameAs(signature);
				}

				[Test]
				public void Constructor_Should_SetProperties()
				{
					// Arrange
					var signature = createRsaSignature();

					// Act
					var obj = new RsaCertificate(
						parameters: Scenario.DefaultRsaParameters,
						signCertificateCallback: (_hash) => signature);
					var rsa = obj.CreateRsa();
					var rsaParameters = rsa.ExportParameters(false);

					// Assert
					rsaParameters.Exponent.SequenceEqual(Scenario.DefaultRsaParameters.Exponent).Should().BeTrue();
					rsaParameters.Modulus.SequenceEqual(Scenario.DefaultRsaParameters.Modulus).Should().BeTrue();
					obj.Signature.Should().BeSameAs(signature);
				}
			}

			public class ConstructorsWithISignature
			{
				[Test]
				public void SignatureNull_ShouldThrow_ArgumentNullException()
				{
					// Arrange
					// Act & Assert
					Assert.Throws<ArgumentNullException>(() => createWithSignature(makeSignatureNull: true));
				}

				[Test]
				public void SignatureWithCorrectDataHash_Should_SetProperties()
				{
					// Arrange
					var signature = createRsaSignature();

					// Act
					var obj = createWithSignature(signature: signature);

					// Assert
					obj.Signature.Should().BeSameAs(signature);
				}

				[Test]
				public void Constructor_Should_SetProperties()
				{
					// Arrange
					var signature = createRsaSignature();

					// Act
					var obj = new RsaCertificate(
						parameters: Scenario.DefaultRsaParameters,
						signature: signature);
					var rsa = obj.CreateRsa();
					var rsaParameters = rsa.ExportParameters(false);

					// Assert
					rsaParameters.Exponent.SequenceEqual(Scenario.DefaultRsaParameters.Exponent).Should().BeTrue();
					rsaParameters.Modulus.SequenceEqual(Scenario.DefaultRsaParameters.Modulus).Should().BeTrue();
					obj.Signature.Should().BeSameAs(signature);
				}
			}

			public class Hashing
			{
				[Test]
				public void HashFromSameCertificateParameters_Should_ComputeSameHashes()
				{
					// Arrange
					var certificate1 = createWithSignature();
					var certificate2 = createWithSignature();

					// Act
					// Assert
					certificate1.Hash.Hash.SequenceEqual(certificate2.Hash.Hash).Should().BeTrue();
				}

				[Test]
				public void HashFromDifferentCertificateParameters_Should_ComputeDifferentHashes()
				{
					// Arrange
					var certificate1 = createWithSignature();
					var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
					var rsaParameters = rsa.ExportParameters(false);
					var certificate2 = createWithSignature(parameters: rsaParameters);

					// Act
					// Assert
					certificate1.Hash.Equals(certificate2.Hash).Should().BeFalse();
				}

				[Test]
				public void CertificatesWithDifferentSignatures_Should_HaveSameHashesButDifferentHashWithSignatures()
				{
					// Arrange
					var signature1 = createRsaSignature();
					var certificate1 = new RsaCertificate(
						parameters: Scenario1.RsaParameters,
						signature: signature1);
					var signature2 = createRsaSignature(
						signerCertificateHash: Sha512Hash.Compute(new byte[] { 0x00 }),
						signature: new byte[] { 0x01 });
					var certificate2 = new RsaCertificate(
						parameters: Scenario1.RsaParameters,
						signature: signature2);

					// Act
					// Assert
					certificate1.Hash.Equals(certificate2.Hash).Should().BeTrue();
					certificate1.HashWithSignature.Equals(certificate2.HashWithSignature).Should().BeFalse();
				}
			}

			public class Equality
			{
				[Test]
				public void SameParametersAndSignature_ShouldReturn_True()
				{
					// Arrange
					var signature = new RsaSignature(Sha512Hash.Compute(new byte[] { 0x00 }), new byte[] { 0x01 });
					var certificate1 = new RsaCertificate(
						parameters: Scenario1.RsaParameters,
						signature: signature);
					var certificate2 = new RsaCertificate(
						parameters: Scenario1.RsaParameters,
						signature: signature);

					// Act
					// Assert
					certificate1.Equals(certificate2).Should().BeTrue();
				}

				[Test]
				public void SameParametersAndDifferentSignature_ShouldReturn_False()
				{
					// Arrange
					var signature1 = createRsaSignature();
					var certificate1 = new RsaCertificate(
						parameters: Scenario1.RsaParameters,
						signature: signature1);
					var signature2 = createRsaSignature(
						signerCertificateHash: Sha512Hash.Compute(new byte[] { 0x00 }),
						signature: new byte[] { 0x01 });
					var certificate2 = new RsaCertificate(
						parameters: Scenario1.RsaParameters,
						signature: signature2);

					// Act
					// Assert
					certificate1.Equals(certificate2).Should().BeFalse();
				}

				[Test]
				public void DifferentParametersAndSameSignature_ShouldReturn_False()
				{
					// Arrange
					var signature = createRsaSignature();
					var certificate1 = new RsaCertificate(
						parameters: Scenario1.RsaParameters,
						signature: signature);
					var certificate2 = new RsaCertificate(
						parameters: Scenario2.RsaParameters,
						signature: signature);

					// Act
					// Assert
					certificate1.Equals(certificate2).Should().BeFalse();
				}
			}

			public class GetHashCodeMethod
			{
				[Test]
				public void GetHashCode_ShouldReturn_HashCodeOfHashWithSignatureProperty()
				{
					// Arrange
					var rsa = new RsaCertificate(Scenario1.RsaParameters);

					// Act
					// Assert
					rsa.GetHashCode().Should().Be(rsa.HashWithSignature.GetHashCode());
				}
			}
		}

		public class CreateRsa
		{
			[Test]
			public void Create_ShouldReturn_InitializedRsaCryptoServiceProvider()
			{
				// Arrange
				var certificate = new RsaCertificate(Scenario1.RsaParameters);

				// Act
				var rsa = certificate.CreateRsa();

				// Assert
				var parameters = rsa.ExportParameters(false);
				parameters.Exponent.SequenceEqual(Scenario1.Exponent).Should().BeTrue();
				parameters.Modulus.SequenceEqual(Scenario1.Modulus).Should().BeTrue();
			}
		}
	}
}
