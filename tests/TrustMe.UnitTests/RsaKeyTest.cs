using FluentAssertions;
using NUnit.Framework;
using System;
using System.Linq;
using System.Text;

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
                    var obj = new RsaKey(parameters: ScenarioRsa.DefaultRsaParameters);

                    // Assert
                    var rsa = obj.CreateRsa();
                    var rsaParameters = rsa.ExportParameters(true);
                    rsaParameters.Modulus.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Modulus).Should().BeTrue();
                    rsaParameters.D.SequenceEqual(ScenarioRsa.DefaultRsaParameters.D).Should().BeTrue();
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
                public void GenerateAndSignCallbackNull_ShouldThrow_ArgumentNullException()
                {
                    // Arrange
                    // Act & Assert
                    Assert.Throws<ArgumentNullException>(() => RsaKey.Generate(signKeyCallback: null));
                }

                [Test]
                public void GenerateAndSignCallback_Should_StoreSignature()
                {
                    // Arrange
                    var signature = new RsaSignature(ScenarioRsa.DefaultSignerCertificate.Hash, new byte[] { 0x11, 0x11, 0x11, 0x11 });

                    // Act
                    var key = RsaKey.Generate((_hash) => signature);

                    // Assert
                    key.Signature.Should().BeSameAs(signature);
                    ((RsaKey)key).Signature.Should().BeSameAs(((IKey)key).Signature);
                }

                [Test]
                public void GenerateAndSignCallbackWithExceptionInCallback_ShouldThrow_Exception()
                {
                    // Arrange
                    // Act & Assert
                    Assert.Throws<InvalidOperationException>(() => RsaKey.Generate((_hash) => throw new InvalidOperationException()));
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
                    var signedCertificate = key.Sign(certificate: ScenarioRsa.DefaultCertificate);

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
                    var validatorCertificate = validatorKey.DeriveCertificate();
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
                    var certificateRsaParameters = ScenarioRsa.DefaultKey.DeriveCertificate().CreateRsa().ExportParameters(false);

                    // Assert
                    certificateRsaParameters.Exponent.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Exponent).Should().BeTrue();
                    certificateRsaParameters.Modulus.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Modulus).Should().BeTrue();
                    // Certificates may not export private RSA cryptographic parameters.
                    Assert.Throws(Is.InstanceOf<Exception>(), () => ScenarioRsa.DefaultKey.DeriveCertificate().CreateRsa().ExportParameters(true));
                }
            }

            public class EncryptionRoundtrip
            {
                [Test]
                public void EncryptPlainTextNull_ShouldThrow_ArgumentNullException()
                {
                    // Arrange
                    // Act & Assert
                    Assert.Throws<ArgumentNullException>(
                        () => ScenarioRsa.DefaultCertificate.Encrypt(plainText: null));
                }

                [Test]
                public void DecryptCipherNull_ShouldThrow_ArgumentNullException()
                {
                    // Arrange
                    var originalPlainText = Encoding.ASCII.GetBytes(
                        new string('x', ScenarioRsa.DefaultCertificate.GetMaximumPlainTextLengthForEncryption() / 2));

                    // Act
                    var cipher = ScenarioRsa.DefaultCertificate.Encrypt(plainText: originalPlainText);
                    var plainText = ScenarioRsa.DefaultKey.Decrypt(cipher: cipher);

                    // Assert
                    plainText.SequenceEqual(originalPlainText).Should().BeTrue();
                }

                [Test]
                public void EncryptDecryptKeySizedPlainText_Should_Succeed()
                {
                    // Arrange
                    var originalPlainText = Encoding.ASCII.GetBytes(
                        new string('x', ScenarioRsa.DefaultCertificate.GetMaximumPlainTextLengthForEncryption()));

                    // Act
                    var cipher = ScenarioRsa.DefaultCertificate.Encrypt(plainText: originalPlainText);
                    var plainText = ScenarioRsa.DefaultKey.Decrypt(cipher: cipher);

                    // Assert
                    plainText.SequenceEqual(originalPlainText).Should().BeTrue();
                }

                [Test]
                public void DecryptLessThanKeySizedPlainText_ShouldThrow_ArgumentOutOfRangeException()
                {
                    // Arrange
                    var cipher = Encoding.ASCII.GetBytes(
                        new string('x', RsaKey.KeySize / 8 / 2));

                    // Act & Assert
                    Assert.Throws<ArgumentOutOfRangeException>(() => ScenarioRsa.DefaultKey.Decrypt(cipher: cipher));
                }

                [Test]
                public void DecryptExactlyKeySizedButInvalidPlainText_ShouldThrow_ArgumentException()
                {
                    // Arrange
                    var cipher = Encoding.ASCII.GetBytes(
                        new string('x', RsaKey.KeySize / 8));

                    // Act & Assert
                    Assert.Throws<ArgumentException>(() => ScenarioRsa.DefaultKey.Decrypt(cipher: cipher));
                }

                [Test]
                public void DecryptMoreThanKeySizedPlainText_ShouldThrow_ArgumentOutOfRangeException()
                {
                    // Arrange
                    var cipher = Encoding.ASCII.GetBytes(
                        new string('x', RsaKey.KeySize / 8 + 1));

                    // Act & Assert
                    Assert.Throws<ArgumentOutOfRangeException>(() => ScenarioRsa.DefaultKey.Decrypt(cipher: cipher));
                }
            }
        }

        class HashableString : IHashable
        {
            public string Text { get; set; }

            public IHash ComputeHash()
            {
                return Sha512Hash.Compute(Encoding.UTF8.GetBytes(this.Text));
            }
        }

        public class WithEmbeddedData
        {
            public class Constructors
            {
                [Test]
                public void Constructor_Should_SetProperties()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act
                    var key = new RsaKey<HashableString>(parameters: ScenarioRsa.DefaultRsaParameters, embeddedData: embeddedData);

                    // Assert
                    ((IKey<HashableString>)key).EmbeddedDataTyped.Should().BeSameAs(embeddedData);
                }

                [Test]
                public void EmbeddedDataNull_Should_Succeed()
                {
                    // Arrange
                    // Act
                    // Assert
                    new RsaKey(parameters: ScenarioRsa.DefaultRsaParameters, embeddedData: null);
                }

                [Test]
                public void WithAndWithoutEmbeddedData_Should_HaveDifferentHashes()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act
                    var keyWithoutEmbeddedData = new RsaKey(parameters: ScenarioRsa.DefaultRsaParameters);
                    var keyWithEmbeddedData = new RsaKey<HashableString>(parameters: ScenarioRsa.DefaultRsaParameters, embeddedData: embeddedData);

                    // Assert
                    keyWithoutEmbeddedData.Hash.Equals(keyWithEmbeddedData.Hash).Should().BeFalse();
                }

                [Test]
                public void DifferentEmbeddedData_Should_HaveDifferentHashes()
                {
                    // Arrange
                    var embeddedData1 = new HashableString { Text = "test1" };
                    var embeddedData2 = new HashableString { Text = "test2" };

                    // Act
                    var keyWithEmbeddedData1 = new RsaKey<HashableString>(parameters: ScenarioRsa.DefaultRsaParameters, embeddedData: embeddedData1);
                    var keyWithEmbeddedData2 = new RsaKey<HashableString>(parameters: ScenarioRsa.DefaultRsaParameters, embeddedData: embeddedData2);

                    // Assert
                    keyWithEmbeddedData1.Hash.Equals(keyWithEmbeddedData2.Hash).Should().BeFalse();
                }

                [Test]
                public void EmbeddedDataViaHashOrGenerics_Should_HaveSameHash()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act
                    var objWithHash = new RsaKey(parameters: ScenarioRsa.DefaultRsaParameters, embeddedData: embeddedData);
                    var objWithGenerics = new RsaKey<HashableString>(parameters: ScenarioRsa.DefaultRsaParameters, embeddedData: embeddedData);

                    // Assert
                    objWithHash.Hash.Equals(objWithGenerics.Hash).Should().BeTrue();
                }
            }

            public class Generation
            {
                [Test]
                public void GenerateWithEmbeddedDataNull_Should_Succeed()
                {
                    // Arrange
                    // Act
                    // Assert
                    RsaKey.Generate(embeddedData: null);
                }

                [Test]
                public void GenerateWithGenericEmbeddedDataNull_Should_Succeed()
                {
                    // Arrange
                    // Act
                    // Assert
                    RsaKey<HashableString>.Generate(embeddedData: (HashableString)null);
                }

                [Test]
                public void GenerateWithEmbeddedDataHashWithoutSignature_Should_Succeed()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act
                    var key = RsaKey.Generate(embeddedData: embeddedData);

                    // Assert
                    key.EmbeddedData.Should().BeSameAs(embeddedData);
                }

                [Test]
                public void GenerateWithEmbeddedDataHashAndSignCallbackNull_ShouldThrow_ArgumentNullException()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act & Assert
                    Assert.Throws<ArgumentNullException>(() => RsaKey.Generate(embeddedData: embeddedData, signKeyCallback: null));
                }

                [Test]
                public void GenerateWithEmbeddedDataHashAndSignCallback_Should_StoreSignature()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };
                    var signature = new RsaSignature(ScenarioRsa.DefaultSignerCertificate.Hash, new byte[] { 0x11, 0x11, 0x11, 0x11 });

                    // Act
                    var key = RsaKey.Generate(embeddedData: embeddedData, signKeyCallback: (_hash) => signature);

                    // Assert
                    key.EmbeddedData.Should().BeSameAs(embeddedData);
                    key.Signature.Should().BeSameAs(signature);
                }

                [Test]
                public void GenerateWithEmbeddedDataHashAndSignCallbackWithExceptionInCallback_ShouldThrow_Exception()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act & Assert
                    Assert.Throws<InvalidOperationException>(() => RsaKey.Generate(embeddedData: embeddedData, signKeyCallback: (_hash) => throw new InvalidOperationException()));
                }

                [Test]
                public void GenerateWithGenericEmbeddedDataWithoutSignature_Should_Succeed()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act
                    var key = RsaKey<HashableString>.Generate(embeddedData: embeddedData);

                    // Assert
                    key.EmbeddedData.Should().BeSameAs(embeddedData);
                }

                [Test]
                public void GenerateWithGenericEmbeddedDataAndSignCallbackNull_ShouldThrow_ArgumentNullException()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act & Assert
                    Assert.Throws<ArgumentNullException>(() => RsaKey<HashableString>.Generate(embeddedData: embeddedData, signKeyCallback: null));
                }

                [Test]
                public void GenerateWithGenericEmbeddedDataAndSignCallback_Should_StoreSignature()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };
                    var signature = new RsaSignature(ScenarioRsa.DefaultSignerCertificate.Hash, new byte[] { 0x11, 0x11, 0x11, 0x11 });

                    // Act
                    var key = RsaKey<HashableString>.Generate(embeddedData: embeddedData, signKeyCallback: (_hash) => signature);

                    // Assert
                    ((RsaKey<HashableString>)key).EmbeddedDataTyped.Should().BeSameAs(embeddedData);
                    ((IKey<HashableString>)key).EmbeddedDataTyped.Should().BeSameAs(embeddedData);
                    key.Signature.Should().BeSameAs(signature);
                }

                [Test]
                public void GenerateWithGenericEmbeddedDataAndSignCallbackWithExceptionInCallback_ShouldThrow_Exception()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };

                    // Act & Assert
                    Assert.Throws<InvalidOperationException>(() => RsaKey<HashableString>.Generate(embeddedData: embeddedData, signKeyCallback: (_hash) => throw new InvalidOperationException()));
                }
            }

            public class CertificateDerivation
            {
                [Test]
                public void DeriveWithoutEmbeddedData_Should_CreateCertificateWithSameRsaExponentAndModulusButNoPrivateKeyParameters()
                {
                    // Arrange
                    // Act
                    var certificateRsaParameters = ScenarioRsa.DefaultKey.DeriveCertificate().CreateRsa().ExportParameters(false);

                    // Assert
                    certificateRsaParameters.Exponent.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Exponent).Should().BeTrue();
                    certificateRsaParameters.Modulus.SequenceEqual(ScenarioRsa.DefaultRsaParameters.Modulus).Should().BeTrue();
                    // Certificates may not export private RSA cryptographic parameters.
                    Assert.Throws(Is.InstanceOf<Exception>(), () => ScenarioRsa.DefaultKey.DeriveCertificate().CreateRsa().ExportParameters(true));
                }

                [Test]
                public void DeriveWithEmbeddedData_Should_ReflectEmbeddedDataInCertificate()
                {
                    // Arrange
                    var embeddedData = new HashableString { Text = "test" };
                    var key = RsaKey.Generate(embeddedData);

                    // Act
                    var certificate = key.DeriveCertificate();

                    // Assert
                    certificate.Should().BeOfType<RsaCertificate>();
                    ((HashableString)certificate.EmbeddedData).Text.Should().Be("test");
                    certificate.EmbeddedData.ComputeHash().Equals(key.EmbeddedData.ComputeHash()).Should().BeTrue();
                }

                [Test]
                public void DeriveWithGenericEmbeddedData_Should_ReflectEmbeddedDataInCertificate()
                {
                    // Arrange
                    var key = RsaKey<HashableString>.Generate(new HashableString { Text = "test" });

                    // Act
                    var certificate = key.DeriveCertificate();

                    // Assert
                    certificate.Should().BeOfType<RsaCertificate<HashableString>>();
                    certificate.EmbeddedDataTyped.Text.Should().Be("test");
                    certificate.EmbeddedData.ComputeHash().Equals(key.EmbeddedData.ComputeHash()).Should().BeTrue();
                }
            }
        }
    }
}
