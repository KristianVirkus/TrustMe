using FluentAssertions;
using NUnit.Framework;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace TrustMe.UnitTests
{
	class RsaSignatureTest
	{
		static RsaSignature create(
			IHash dataHash = null,
			IHash signerCertificateHash = null, bool makeSignerCertificateHashNull = false,
			byte[] signature = null, bool makeSignatureNull = false)
		{
			dataHash = dataHash ?? ScenarioRsa.DefaultDataHash;
			if ((signature == null) && (!makeSignatureNull))
			{
				using (var rsa = ScenarioRsa.DefaultKey.CreateRsa())
				{
					signature = rsa.SignHash(dataHash.Hash.ToArray(), dataHash.Name, RSASignaturePadding.Pkcs1);
				}
			}

			return new RsaSignature(
				signerCertificateHash: signerCertificateHash ?? (makeSignerCertificateHashNull ? null : ScenarioRsa.DefaultKey.Hash),
				signature: signature);
		}

		public class Constructors
		{
			[Test]
			public void SignerCertificateHashNull_ShouldThrow_ArgumentNullException()
			{
				// Arrange
				// Act
				// Assert
				Assert.Throws<ArgumentNullException>(() => create(makeSignerCertificateHashNull: true));
			}

			[Test]
			public void SignatureNull_ShouldThrow_ArgumentNullException()
			{
				// Arrange
				// Act
				// Assert
				Assert.Throws<ArgumentNullException>(() => create(makeSignatureNull: true));
			}

			[Test]
			public void Constructor_Should_SetProperties()
			{
				// Arrange
				// Act
				var signature = create();

				// Assert
				signature.SignerCertificateHash.Hash.SequenceEqual(ScenarioRsa.DefaultKey.Hash.Hash).Should().BeTrue();
				signature.Signature.Should().NotBeNull();
			}
		}

		public class Equality
		{
			[Test]
			public void EqualsNullObject_ShouldReturn_False()
			{
				// Arrange
				var signature = create();

				// Act
				// Assert
				signature.Equals((object)null).Should().BeFalse();
			}

			[Test]
			public void EqualsNullISignature_ShouldReturn_False()
			{
				// Arrange
				var signature = create();

				// Act
				// Assert
				signature.Equals((ISignature)null).Should().BeFalse();
			}

			[Test]
			public void EqualsSameDataObject_ShouldReturn_True()
			{
				// Arrange
				var signature1 = create();
				var signature2 = create();

				// Act
				// Assert
				signature1.Equals((object)signature2).Should().BeTrue();
			}

			[Test]
			public void EqualsSameDataISignature_ShouldReturn_True()
			{
				// Arrange
				var signature1 = create();
				var signature2 = create();

				// Act
				// Assert
				signature1.Equals((ISignature)signature2).Should().BeTrue();
			}

			[Test]
			public void SameSignerCertificateHashAndDifferentSignature_ShouldReturn_False()
			{
				// Arrange
				var signature1 = create();
				var signature2 = create(signature: new byte[] { 0x44, 0x33, 0x22, 0x11 });

				// Act
				// Assert
				signature1.Equals(signature2).Should().BeFalse();
			}

			[Test]
			public void DifferentSignerCertificateHashAndSameSignature_ShouldReturn_False()
			{
				// Arrange
				var signature1 = create();
				var signature2 = create(signerCertificateHash: Sha512Hash.Compute(new byte[] { 0x4f, 0x3f, 0x2f, 0x1f }));

				// Act
				// Assert
				signature1.Equals(signature2).Should().BeFalse();
			}
		}

		public class GetHashCodeMethod
		{
			[Test]
			public void SameData_ShouldReturn_SameHashCode()
			{
				// Arrange
				var signature1 = create();
				var signature2 = create();

				// Act
				// Assert
				signature1.GetHashCode().Should().Be(signature2.GetHashCode());
			}

			[Test]
			public void SameSignerCertificateHashAndDifferentSignature_ShouldReturn_DifferentHashCodes()
			{
				// Arrange
				var signature1 = create();
				var signature2 = create(signature: new byte[] { 0x44, 0x33, 0x22, 0x11 });

				// Act
				// Assert
				signature1.GetHashCode().Should().NotBe(signature2.GetHashCode());
			}

			[Test]
			public void DifferentSignerCertificateHashAndSameSignature_ShouldReturn_DifferentHashCodes()
			{
				// Arrange
				var signature1 = create();
				var signature2 = create(signerCertificateHash: Sha512Hash.Compute(new byte[] { 0x4f, 0x3f, 0x2f, 0x1f }));

				// Act
				// Assert
				signature1.GetHashCode().Should().NotBe(signature2.GetHashCode());
			}
		}
	}
}
