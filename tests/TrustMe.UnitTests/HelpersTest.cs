using FluentAssertions;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;

namespace TrustMe.UnitTests
{
	class HelpersTest
	{
		public class ComputeRsaHash
		{
			[Test]
			public void SameArguments_ShouldReturn_SameHash()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHash(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData });
				var hash2 = Helpers.ComputeRsaHash(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData });

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeTrue();
			}

			[Test]
			public void DifferentRsaParameters_ShouldReturn_DifferentHashes()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHash(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData });
				var otherRsaParameters = new RSACryptoServiceProvider().ExportParameters(true);
				var hash2 = Helpers.ComputeRsaHash(
					rsaParameters: otherRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData });

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeFalse();
			}

			[Test]
			public void DifferentPrivateParametersWhileNotIncludePrivateParameters_ShouldReturn_SameHash()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHash(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: false,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData });
				var otherRsaParameters = new RSACryptoServiceProvider().ExportParameters(true);
				otherRsaParameters.Exponent = ScenarioRsa.DefaultRsaParameters.Exponent;
				otherRsaParameters.Modulus = ScenarioRsa.DefaultRsaParameters.Modulus;
				var hash2 = Helpers.ComputeRsaHash(
					rsaParameters: otherRsaParameters,
					includePrivateParameters: false,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData });

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeTrue();
			}

			[Test]
			public void DifferentEmbeddedData_ShouldReturn_DifferentHashes()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHash(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData });
				var hash2 = Helpers.ComputeRsaHash(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = new byte[] { 0x12, 0x23, 0x34, 0x45 } });

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeFalse();
			}
		}

		public class ComputeRsaHashWithSignature
		{
			[Test]
			public void SameArguments_ShouldReturn_SameHash()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: ScenarioRsa.DefaultSignature);
				var hash2 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: ScenarioRsa.DefaultSignature);

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeTrue();
			}

			[Test]
			public void DifferentRsaParameters_ShouldReturn_DifferentHashes()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: ScenarioRsa.DefaultSignature);
				var otherRsaParameters = new RSACryptoServiceProvider().ExportParameters(true);
				var hash2 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: otherRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: ScenarioRsa.DefaultSignature);

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeFalse();
			}

			[Test]
			public void DifferentPrivateParametersWhileNotIncludePrivateParameters_ShouldReturn_SameHash()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: false,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: ScenarioRsa.DefaultSignature);
				var otherRsaParameters = new RSACryptoServiceProvider().ExportParameters(true);
				otherRsaParameters.Exponent = ScenarioRsa.DefaultRsaParameters.Exponent;
				otherRsaParameters.Modulus = ScenarioRsa.DefaultRsaParameters.Modulus;
				var hash2 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: otherRsaParameters,
					includePrivateParameters: false,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: ScenarioRsa.DefaultSignature);

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeTrue();
			}

			[Test]
			public void DifferentEmbeddedData_ShouldReturn_DifferentHashes()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: ScenarioRsa.DefaultSignature);
				var hash2 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = new byte[] { 0x12, 0x23, 0x34, 0x45 } },
					signature: ScenarioRsa.DefaultSignature);

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeFalse();
			}

			[Test]
			public void DifferentSignatures_ShouldReturn_DifferentHashes()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: ScenarioRsa.DefaultSignature);
				var hash2 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: new RsaSignature(Sha512Hash.Compute(new byte[] { 0xaa, 0xbb, 0xcc, 0xdd }), new byte[] { 0x1a, 0x2b, 0x3c, 0x4d }));

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeFalse();
			}

			[Test]
			public void NoSignatures_ShouldReturn_SameHash()
			{
				// Arrange
				var hash1 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: null);
				var hash2 = Helpers.ComputeRsaHashWithSignature(
					rsaParameters: ScenarioRsa.DefaultRsaParameters,
					includePrivateParameters: true,
					embeddedData: new TestHashable { Data = ScenarioRsa.DefaultEmbeddedData },
					signature: null);

				// Act
				// Assert
				hash1.Hash.SequenceEqual(hash2.Hash).Should().BeTrue();
			}
		}

		class TestHashable : IHashable
		{
			public byte[] Data { get; set; }
			public IHash ComputeHash() => Sha512Hash.Compute(this.Data);
		}
	}
}
