using FluentAssertions;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TrustMe.UnitTests
{
    static class RsaCertificateTest
    {
        static RsaCertificate create(
            RSAParameters? parameters = null)
        => new RsaCertificate(
            parameters: parameters ?? ScenarioRsa.DefaultRsaParameters);

        static RsaCertificate createWithEmbeddedData(
            RSAParameters? parameters = null,
            IEnumerable<byte> embeddedData = null, bool makeEmbeddedDataNull = false)
        => new RsaCertificate(
            parameters: parameters ?? ScenarioRsa.DefaultRsaParameters,
            embeddedData: embeddedData ?? (makeEmbeddedDataNull ? null : ScenarioRsa.DefaultEmbeddedData));

        static RsaCertificate createWithSignature(
            RSAParameters? parameters = null,
            RsaSignature signature = null, bool makeSignatureNull = false)
        => new RsaCertificate(
            parameters: parameters ?? ScenarioRsa.DefaultRsaParameters,
            signature: signature ?? (makeSignatureNull ? null : ScenarioRsa.DefaultSignature));

        static RsaCertificate createWithEmbeddedDataAndSignature(
            RSAParameters? parameters = null,
            IEnumerable<byte> embeddedData = null, bool makeEmbeddedDataNull = false,
            RsaSignature signature = null, bool makeSignatureNull = false)
        => new RsaCertificate(
            parameters: parameters ?? ScenarioRsa.DefaultRsaParameters,
            embeddedData: embeddedData ?? (makeEmbeddedDataNull ? null : ScenarioRsa.DefaultEmbeddedData),
            signature: signature ?? (makeSignatureNull ? null : ScenarioRsa.DefaultSignature));

        static RsaCertificate createWithSignatureCallback(
            RSAParameters? parameters = null,
            Func<IHash, RsaSignature> signCertificateCallback = null, bool makeSignCertificateCallbackNull = false)
        => new RsaCertificate(
            parameters: parameters ?? ScenarioRsa.DefaultRsaParameters,
            signCertificateCallback: signCertificateCallback ?? (makeSignCertificateCallbackNull ? (Func<IHash, RsaSignature>)null : (_hash) => createRsaSignature()));

        static RsaCertificate createWithEmbeddedDataAndSignatureCallback(
            RSAParameters? parameters = null,
            IEnumerable<byte> embeddedData = null, bool makeEmbeddedDataNull = false,
            Func<IHash, RsaSignature> signCertificateCallback = null, bool makeSignCertificateCallbackNull = false)
        => new RsaCertificate(
            parameters: parameters ?? ScenarioRsa.DefaultRsaParameters,
            embeddedData: embeddedData ?? (makeEmbeddedDataNull ? null : ScenarioRsa.DefaultEmbeddedData),
            signCertificateCallback: signCertificateCallback ?? (makeSignCertificateCallbackNull ? (Func<IHash, RsaSignature>)null : (_hash) => createRsaSignature()));

        static RsaSignature createRsaSignature(
            IHash signerCertificateHash = null, bool makeSignerCertificateHashNull = false,
            byte[] signature = null, bool makeSignatureNull = false)
        => new RsaSignature(
            signerCertificateHash: signerCertificateHash ?? (makeSignerCertificateHashNull ? null : ScenarioRsa.DefaultSignerCertificate.Hash),
            signature: signature ?? (makeSignatureNull ? null : ScenarioRsa.DefaultSignatureData));

        public class WithoutSignature
        {
            public class ConstructorsWithSignatureCallback
            {
                [Test]
                public void Constructor_Should_SetProperties()
                {
                    // Arrange
                    // Act
                    var obj = new RsaCertificate(parameters: ScenarioRsa.DefaultRsaParameters);
                    var rsa = obj.CreateRsa();
                    var rsaParameters = rsa.ExportParameters(false);

                    // Assert
                    rsaParameters.Exponent.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Exponent).Should().BeTrue();
                    rsaParameters.Modulus.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Modulus).Should().BeTrue();
                }
            }

            public class Hashing
            {
                [Test]
                public void HashFromSameCertificateParameters_Should_ComputeSameHashes()
                {
                    // Arrange
                    var certificate1 = create();
                    var certificate2 = create();

                    // Act
                    // Assert
                    certificate1.Hash.Hash.SequenceEqual(certificate2.Hash.Hash).Should().BeTrue();
                }

                [Test]
                public void HashFromDifferentCertificateParameters_Should_ComputeDifferentHashes()
                {
                    // Arrange
                    var certificate1 = create();
                    var rsa = new RSACryptoServiceProvider(RsaKey.KeySize);
                    var rsaParameters = rsa.ExportParameters(false);
                    var certificate2 = create(parameters: rsaParameters);

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
                    var certificate1 = new RsaCertificate(parameters: ScenarioRsa1.RsaParameters);
                    var certificate2 = new RsaCertificate(parameters: ScenarioRsa1.RsaParameters);

                    // Act
                    // Assert
                    certificate1.Equals(certificate2).Should().BeTrue();
                }

                [Test]
                public void DifferentParameters_ShouldReturn_False()
                {
                    // Arrange
                    var certificate1 = new RsaCertificate(parameters: ScenarioRsa1.RsaParameters);
                    var certificate2 = new RsaCertificate(parameters: ScenarioRsa2.RsaParameters);

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
                    var rsa = new RsaCertificate(ScenarioRsa1.RsaParameters);

                    // Act
                    // Assert
                    rsa.GetHashCode().Should().Be(rsa.HashWithSignature.GetHashCode());
                }
            }

            public class EmbeddedData
            {
                [Test]
                public void ConstructorEmbeddedDataNull_Should_SucceedAndHaveSameHashAsWithEmbeddedDatalessConstructor()
                {
                    // Arrange
                    // Act
                    var certificateWithoutEmbeddedData = create();
                    var certificateWithEmbeddedDataNull = createWithEmbeddedData(makeEmbeddedDataNull: true);

                    // Assert
                    certificateWithoutEmbeddedData.Hash.Equals(certificateWithEmbeddedDataNull.Hash).Should().BeTrue();
                }

                [Test]
                public void Constructor_Should_Succeed()
                {
                    // Arrange
                    var embeddedData = new byte[] { 0x10, 0x20, 0x30, 0x40 };

                    // Act
                    var certificate = createWithEmbeddedData(embeddedData: embeddedData);

                    // Assert
                    certificate.EmbeddedData.SequenceEqual(embeddedData).Should().BeTrue();
                }

                [Test]
                public void DifferentEmbeddedData_Should_ComputeDifferentCertificateHashes()
                {
                    // Arrange
                    var embeddedData1 = new byte[] { 0x10, 0x20, 0x30, 0x40 };
                    var embeddedData2 = new byte[] { 0x17, 0x27, 0x37, 0x47 };

                    // Act
                    var certificate1 = createWithEmbeddedData(embeddedData: embeddedData1);
                    var certificate2 = createWithEmbeddedData(embeddedData: embeddedData2);

                    // Assert
                    certificate1.Hash.Equals(certificate2.Hash).Should().BeFalse();
                }
            }

            public class Encryption
            {
                [Test]
                public void EncryptMoreThanKeySizedPlainText_ShouldThrow_ArgumentOutOfRangeException()
                {
                    // Arrange
                    var plainText = Encoding.ASCII.GetBytes(
                        new string('x', ScenarioRsa.DefaultCertificate.GetMaximumPlainTextLengthForEncryption() + 1));

                    // Act & Assert
                    Assert.Throws<ArgumentOutOfRangeException>(
                        () => ScenarioRsa.DefaultCertificate.Encrypt(plainText: plainText));
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
                        parameters: ScenarioRsa.DefaultRsaParameters,
                        signCertificateCallback: (_hash) => signature);
                    var rsa = obj.CreateRsa();
                    var rsaParameters = rsa.ExportParameters(false);

                    // Assert
                    rsaParameters.Exponent.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Exponent).Should().BeTrue();
                    rsaParameters.Modulus.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Modulus).Should().BeTrue();
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
                        parameters: ScenarioRsa.DefaultRsaParameters,
                        signature: signature);
                    var rsa = obj.CreateRsa();
                    var rsaParameters = rsa.ExportParameters(false);

                    // Assert
                    rsaParameters.Exponent.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Exponent).Should().BeTrue();
                    rsaParameters.Modulus.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Modulus).Should().BeTrue();
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
                        parameters: ScenarioRsa1.RsaParameters,
                        signature: signature1);
                    var signature2 = createRsaSignature(
                        signerCertificateHash: Sha512Hash.Compute(new byte[] { 0x00 }),
                        signature: new byte[] { 0x01 });
                    var certificate2 = new RsaCertificate(
                        parameters: ScenarioRsa1.RsaParameters,
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
                        parameters: ScenarioRsa1.RsaParameters,
                        signature: signature);
                    var certificate2 = new RsaCertificate(
                        parameters: ScenarioRsa1.RsaParameters,
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
                        parameters: ScenarioRsa1.RsaParameters,
                        signature: signature1);
                    var signature2 = createRsaSignature(
                        signerCertificateHash: Sha512Hash.Compute(new byte[] { 0x00 }),
                        signature: new byte[] { 0x01 });
                    var certificate2 = new RsaCertificate(
                        parameters: ScenarioRsa1.RsaParameters,
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
                        parameters: ScenarioRsa1.RsaParameters,
                        signature: signature);
                    var certificate2 = new RsaCertificate(
                        parameters: ScenarioRsa2.RsaParameters,
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
                    var rsa = new RsaCertificate(ScenarioRsa1.RsaParameters);

                    // Act
                    // Assert
                    rsa.GetHashCode().Should().Be(rsa.HashWithSignature.GetHashCode());
                }
            }

            public class EmbeddedDataAndISignature
            {
                [Test]
                public void ConstructorEmbeddedDataNull_Should_SucceedAndHaveSameHashAsWithEmbeddedDatalessConstructor()
                {
                    // Arrange
                    // Act
                    var certificateWithoutEmbeddedData = createWithSignature();
                    var certificateWithEmbeddedDataNull = createWithEmbeddedDataAndSignature(makeEmbeddedDataNull: true);

                    // Assert
                    certificateWithoutEmbeddedData.Hash.Equals(certificateWithEmbeddedDataNull.Hash).Should().BeTrue();
                }

                [Test]
                public void Constructor_Should_Succeed()
                {
                    // Arrange
                    var embeddedData = new byte[] { 0x10, 0x20, 0x30, 0x40 };

                    // Act
                    var certificate = createWithEmbeddedDataAndSignature(embeddedData: embeddedData);

                    // Assert
                    certificate.EmbeddedData.SequenceEqual(embeddedData).Should().BeTrue();
                }

                [Test]
                public void DifferentEmbeddedData_Should_ComputeDifferentCertificateHashes()
                {
                    // Arrange
                    var embeddedData1 = new byte[] { 0x10, 0x20, 0x30, 0x40 };
                    var embeddedData2 = new byte[] { 0x17, 0x27, 0x37, 0x47 };

                    // Act
                    var certificate1 = createWithEmbeddedDataAndSignature(embeddedData: embeddedData1);
                    var certificate2 = createWithEmbeddedDataAndSignature(embeddedData: embeddedData2);

                    // Assert
                    certificate1.Hash.Equals(certificate2.Hash).Should().BeFalse();
                }
            }

            public class EmbeddedDataAndSignatureCallback
            {
                [Test]
                public void ConstructorEmbeddedDataNull_Should_SucceedAndHaveSameHashAsWithEmbeddedDatalessConstructor()
                {
                    // Arrange
                    // Act
                    var certificateWithoutEmbeddedData = createWithSignatureCallback();
                    var certificateWithEmbeddedDataNull = createWithEmbeddedDataAndSignatureCallback(makeEmbeddedDataNull: true);

                    // Assert
                    certificateWithoutEmbeddedData.Hash.Equals(certificateWithEmbeddedDataNull.Hash).Should().BeTrue();
                }

                [Test]
                public void Constructor_Should_Succeed()
                {
                    // Arrange
                    var embeddedData = new byte[] { 0x10, 0x20, 0x30, 0x40 };

                    // Act
                    var certificate = createWithEmbeddedDataAndSignatureCallback(embeddedData: embeddedData);

                    // Assert
                    certificate.EmbeddedData.SequenceEqual(embeddedData).Should().BeTrue();
                }

                [Test]
                public void DifferentEmbeddedData_Should_ComputeDifferentCertificateHashes()
                {
                    // Arrange
                    var embeddedData1 = new byte[] { 0x10, 0x20, 0x30, 0x40 };
                    var embeddedData2 = new byte[] { 0x17, 0x27, 0x37, 0x47 };

                    // Act
                    var certificate1 = createWithEmbeddedDataAndSignatureCallback(embeddedData: embeddedData1);
                    var certificate2 = createWithEmbeddedDataAndSignatureCallback(embeddedData: embeddedData2);

                    // Assert
                    certificate1.Hash.Equals(certificate2.Hash).Should().BeFalse();
                }
            }
        }

        public class CreateRsa
        {
            [Test]
            public void Create_ShouldReturn_InitializedRsaCryptoServiceProvider()
            {
                // Arrange
                var certificate = new RsaCertificate(ScenarioRsa1.RsaParameters);

                // Act
                var rsa = certificate.CreateRsa();

                // Assert
                var parameters = rsa.ExportParameters(false);
                parameters.Exponent.SequenceEqual(ScenarioRsa1.Exponent).Should().BeTrue();
                parameters.Modulus.SequenceEqual(ScenarioRsa1.Modulus).Should().BeTrue();
            }
        }

        public class Derivation
        {
            [Test]
            public void DeriveCertificateFromKey_Should_HaveSameHash()
            {
                // Arrange
                var key = RsaKey.Generate();

                // Act
                var certificate = key.DeriveCertificate();

                // Assert
                certificate.Hash.Equals(key.Hash);
            }
        }
    }
}
