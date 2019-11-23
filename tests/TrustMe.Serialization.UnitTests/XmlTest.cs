using FluentAssertions;
using NUnit.Framework;
using System;
using System.IO;
using System.Linq;

namespace TrustMe.Serialization.UnitTests
{
    static class XmlTest
    {
        public class Serialization
        {
            [Test]
            public void KeyNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                using (var memoryStream = new MemoryStream())
                {
                    // Act & Assert
                    Assert.Throws<ArgumentNullException>(
                        () => Xml.Serialize(
                            certificate: null,
                            stream: memoryStream));
                }
            }

            [Test]
            public void KeyStreamNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(
                    () => Xml.Serialize(
                        certificate: (RsaCertificate)RsaKey.Generate().DeriveCertificate(),
                        stream: null));
            }

            [Test]
            public void CertificateNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                using (var memoryStream = new MemoryStream())
                {
                    // Act & Assert
                    Assert.Throws<ArgumentNullException>(
                        () => Xml.Serialize(
                            certificate: null,
                            stream: memoryStream));
                }
            }

            [Test]
            public void CertificateStreamNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(
                    () => Xml.Serialize(
                        certificate: (RsaCertificate)RsaKey.Generate().DeriveCertificate(),
                        stream: null));
            }
        }

        public class Deserialization
        {
            [Test]
            public void KeyStreamNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => Xml.DeserializeKey(stream: null));
            }

            [Test]
            public void KeyDataInvalid_ShouldThrow_NotSupportedException()
            {
                // Arrange
                using (var memoryStream = new MemoryStream(new byte[] { 0x01, 0x02, 0x03, 0x04 }))
                {
                    // Act & Assert
                    Assert.Throws<NotSupportedException>(
                        () => Xml.DeserializeKey(stream: memoryStream));
                }
            }

            [Test]
            public void CertificateStreamNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => Xml.DeserializeCertificate(stream: null));
            }

            [Test]
            public void CertificateDataInvalid_ShouldThrow_NotSupportedException()
            {
                // Arrange
                using (var memoryStream = new MemoryStream(new byte[] { 0x01, 0x02, 0x03, 0x04 }))
                {
                    // Act & Assert
                    Assert.Throws<NotSupportedException>(
                        () => Xml.DeserializeCertificate(stream: memoryStream));
                }
            }
        }

        public class Roundtrip
        {
            [Test]
            public void KeyRoundtrip_Should_Succeed()
            {
                // Arrange
                var signerKey = RsaKey.Generate();
                var key = RsaKey.Generate(
                    embeddedData: new byte[] { 0xa1, 0xb2, 0xc3, 0xd4 },
                    signKeyCallback: hash => (RsaSignature)signerKey.Sign(hash));

                // Act
                RsaKey deserialized;
                using (var memoryStream = new MemoryStream())
                {
                    Xml.Serialize(
                        key: key,
                        stream: memoryStream);
                    memoryStream.Position = 0;
                    deserialized = (RsaKey)Xml.DeserializeKey(stream: memoryStream);
                }

                // Assert
                deserialized.Hash.Equals(key.Hash).Should().BeTrue();
                deserialized.EmbeddedData.SequenceEqual(key.EmbeddedData).Should().BeTrue();
                deserialized.Signature.SignerCertificateHash.Equals(key.Signature.SignerCertificateHash).Should().BeTrue();
                deserialized.Signature.Signature.SequenceEqual(key.Signature.Signature).Should().BeTrue();
            }

            [Test]
            public void CertificateRoundtrip_Should_Succeed()
            {
                // Arrange
                var signerKey = RsaKey.Generate();
                var key = RsaKey.Generate(
                    embeddedData: new byte[] { 0xa1, 0xb2, 0xc3, 0xd4 },
                    signKeyCallback: hash => (RsaSignature)signerKey.Sign(hash));
                var certificate = (RsaCertificate)key.DeriveCertificate();

                // Act
                RsaCertificate deserialized;
                using (var memoryStream = new MemoryStream())
                {
                    Xml.Serialize(
                        certificate: certificate,
                        stream: memoryStream);
                    memoryStream.Position = 0;
                    deserialized = (RsaCertificate)Xml.DeserializeCertificate(stream: memoryStream);
                }

                // Assert
                deserialized.Hash.Equals(certificate.Hash).Should().BeTrue();
                deserialized.EmbeddedData.SequenceEqual(certificate.EmbeddedData).Should().BeTrue();
                deserialized.Signature.SignerCertificateHash.Equals(certificate.Signature.SignerCertificateHash).Should().BeTrue();
                deserialized.Signature.Signature.SequenceEqual(certificate.Signature.Signature).Should().BeTrue();
            }
        }
    }
}
