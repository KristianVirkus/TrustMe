using FluentAssertions;
using NUnit.Framework;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace TrustMe.Serialization.UnitTests
{
    static class SerializationModelConverterTest
    {
        public class Keys
        {
            [Test]
            public void KeyNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => SerializationModelConverter.Convert(key: null));
            }

            [Test]
            public void ModelNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => SerializationModelConverter.ConvertKeyModel(model: null));
            }

            [Test]
            public void ModelInvalid_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.ConvertKeyModel(model: new SerializationModel
                    {
                        Parameters = new RsaSerializationModel
                        {
                            D = "dGVzdA==",
                            DP = "dGVzdA==",
                            DQ = "dGVzdA==",
                            Exponent = "dGVzdA==",
                            InverseQ = "dGVzdA==",
                            Modulus = "dGVzdA==",
                            P = "dGVzdA==",
                            Q = "dGVzdA==",
                        },
                    }));
            }

            [Test]
            public void ModelIsCertificate_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.ConvertKeyModel(model: new SerializationModel
                    {
                        Hash = "dGVzdA==",
                        EmbeddedData = "dGVzdA==",
                        Parameters = new RsaSerializationModel
                        {
                            D = null,
                            DP = null,
                            DQ = null,
                            Exponent = "dGVzdA==",
                            InverseQ = null,
                            Modulus = "dGVzdA==",
                            P = null,
                            Q = null,
                        },
                        SignerCertificateHash = null,
                        Signature = null,
                    }));
            }

            [Test]
            public void ModelWithoutSignerCertificateHash_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.ConvertKeyModel(model: new SerializationModel
                    {
                        Hash = "dGVzdA==",
                        EmbeddedData = "dGVzdA==",
                        Parameters = new RsaSerializationModel
                        {
                            D = "dGVzdA==",
                            DP = "dGVzdA==",
                            DQ = "dGVzdA==",
                            Exponent = "dGVzdA==",
                            InverseQ = "dGVzdA==",
                            Modulus = "dGVzdA==",
                            P = "dGVzdA==",
                            Q = "dGVzdA==",
                        },
                        SignerCertificateHash = null,
                        Signature = "dGVzdA==",
                    }));
            }

            [Test]
            public void ModelWithoutSignature_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.ConvertKeyModel(model: new SerializationModel
                    {
                        Hash = "dGVzdA==",
                        EmbeddedData = "dGVzdA==",
                        Parameters = new RsaSerializationModel
                        {
                            D = "dGVzdA==",
                            DP = "dGVzdA==",
                            DQ = "dGVzdA==",
                            Exponent = "dGVzdA==",
                            InverseQ = "dGVzdA==",
                            Modulus = "dGVzdA==",
                            P = "dGVzdA==",
                            Q = "dGVzdA==",
                        },
                        SignerCertificateHash = "dGVzdA==",
                        Signature = null,
                    }));
            }
        }

        public class Certificates
        {
            [Test]
            public void CertificateNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => SerializationModelConverter.Convert(certificate: null));
            }

            [Test]
            public void ModelNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => SerializationModelConverter.ConvertCertificateModel(model: null));
            }

            [Test]
            public void ModelInvalid_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.ConvertCertificateModel(model: new SerializationModel()));
            }

            [Test]
            public void ModelIsKey_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.ConvertCertificateModel(model: new SerializationModel
                    {
                        Hash = "dGVzdA==",
                        EmbeddedData = "dGVzdA==",
                        Parameters = new RsaSerializationModel
                        {
                            D = "dGVzdA==",
                            DP = "dGVzdA==",
                            DQ = "dGVzdA==",
                            Exponent = "dGVzdA==",
                            InverseQ = "dGVzdA==",
                            Modulus = "dGVzdA==",
                            P = "dGVzdA==",
                            Q = "dGVzdA==",
                        },
                        SignerCertificateHash = null,
                        Signature = null,
                    }));
            }


            [Test]
            public void ModelWithoutSignerCertificateHash_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.ConvertCertificateModel(model: new SerializationModel
                    {
                        Hash = "dGVzdA==",
                        EmbeddedData = "dGVzdA==",
                        Parameters = new RsaSerializationModel
                        {
                            D = null,
                            DP = null,
                            DQ = null,
                            Exponent = "dGVzdA==",
                            InverseQ = null,
                            Modulus = "dGVzdA==",
                            P = null,
                            Q = null,
                        },
                        SignerCertificateHash = null,
                        Signature = "dGVzdA==",
                    }));
            }

            [Test]
            public void ModelWithoutSignature_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.ConvertCertificateModel(model: new SerializationModel
                    {
                        Hash = "dGVzdA==",
                        EmbeddedData = "dGVzdA==",
                        Parameters = new RsaSerializationModel
                        {
                            D = null,
                            DP = null,
                            DQ = null,
                            Exponent = "dGVzdA==",
                            InverseQ = null,
                            Modulus = "dGVzdA==",
                            P = null,
                            Q = null,
                        },
                        SignerCertificateHash = "dGVzdA==",
                        Signature = null,
                    }));
            }
        }

        public class KeyRoundtrip
        {
            [Test]
            public void WithoutEmbeddedDataAndWithoutSignature_Should_Succeed()
            {
                // Arrange
                var originalKey = RsaKey.Generate();

                // Act
                var model = SerializationModelConverter.Convert(key: originalKey);
                var key = SerializationModelConverter.ConvertKeyModel(model: model);

                // Assert
                System.Convert.FromBase64String(model.Hash).SequenceEqual(originalKey.Hash.Hash).Should().BeTrue();
                key.Hash.Hash.SequenceEqual(originalKey.Hash.Hash).Should().BeTrue();
                model.EmbeddedData.Should().BeNull();
                key.EmbeddedData.Should().BeNull();
                model.SignerCertificateHash.Should().BeNull();
                model.Signature.Should().BeNull();
                key.Signature.Should().BeNull();
            }

            [Test]
            public void WithoutEmbeddedDataButWithSignature_Should_Succeed()
            {
                // Arrange
                var signerKey = RsaKey.Generate();
                var originalKey = RsaKey.Generate(signKeyCallback: hash => (RsaSignature)signerKey.Sign(hash));

                // Act
                var model = SerializationModelConverter.Convert(key: originalKey);
                var key = SerializationModelConverter.ConvertKeyModel(model: model);

                // Assert
                System.Convert.FromBase64String(model.Hash).SequenceEqual(originalKey.Hash.Hash).Should().BeTrue();
                key.Hash.Hash.SequenceEqual(originalKey.Hash.Hash).Should().BeTrue();
                model.EmbeddedData.Should().BeNull();
                key.EmbeddedData.Should().BeNull();
                System.Convert.FromBase64String(model.SignerCertificateHash).SequenceEqual(originalKey.Signature.SignerCertificateHash.Hash).Should().BeTrue();
                System.Convert.FromBase64String(model.Signature).SequenceEqual(originalKey.Signature.Signature).Should().BeTrue();
                key.Signature.SignerCertificateHash.Hash.SequenceEqual(originalKey.Signature.SignerCertificateHash.Hash).Should().BeTrue();
                key.Signature.Signature.SequenceEqual(originalKey.Signature.Signature).Should().BeTrue();
            }

            [Test]
            public void WithEmbeddedDataButWithoutSignature_Should_Succeed()
            {
                // Arrange
                var originalKey = RsaKey.Generate(embeddedData: new byte[] { 0x01, 0x02, 0x03, 0x03 });

                // Act
                var model = SerializationModelConverter.Convert(key: originalKey);
                var key = SerializationModelConverter.ConvertKeyModel(model: model);

                // Assert
                System.Convert.FromBase64String(model.Hash).SequenceEqual(originalKey.Hash.Hash).Should().BeTrue();
                key.Hash.Hash.SequenceEqual(originalKey.Hash.Hash).Should().BeTrue();
                System.Convert.FromBase64String(model.EmbeddedData).SequenceEqual(originalKey.EmbeddedData).Should().BeTrue();
                key.EmbeddedData.SequenceEqual(originalKey.EmbeddedData).Should().BeTrue();
                model.SignerCertificateHash.Should().BeNull();
                model.Signature.Should().BeNull();
                key.Signature.Should().BeNull();
            }

            [Test]
            public void WithEmbeddedDataAndWithSignature_Should_Succeed()
            {
                // Arrange
                var signerKey = RsaKey.Generate();
                var originalKey = RsaKey.Generate(
                    embeddedData: new byte[] { 0x01, 0x02, 0x03, 0x03 },
                    signKeyCallback: hash => (RsaSignature)signerKey.Sign(hash));

                // Act
                var model = SerializationModelConverter.Convert(key: originalKey);
                var key = SerializationModelConverter.ConvertKeyModel(model: model);

                // Assert
                System.Convert.FromBase64String(model.Hash).SequenceEqual(originalKey.Hash.Hash).Should().BeTrue();
                key.Hash.Hash.SequenceEqual(originalKey.Hash.Hash).Should().BeTrue();
                System.Convert.FromBase64String(model.EmbeddedData).SequenceEqual(originalKey.EmbeddedData).Should().BeTrue();
                key.EmbeddedData.SequenceEqual(originalKey.EmbeddedData).Should().BeTrue();
                System.Convert.FromBase64String(model.SignerCertificateHash).SequenceEqual(originalKey.Signature.SignerCertificateHash.Hash).Should().BeTrue();
                System.Convert.FromBase64String(model.Signature).SequenceEqual(originalKey.Signature.Signature).Should().BeTrue();
                key.Signature.SignerCertificateHash.Hash.SequenceEqual(originalKey.Signature.SignerCertificateHash.Hash).Should().BeTrue();
                key.Signature.Signature.SequenceEqual(originalKey.Signature.Signature).Should().BeTrue();
            }
        }

        public class CertificateRoundtrip
        {
            [Test]
            public void WithoutEmbeddedDataAndWithoutSignature_Should_Succeed()
            {
                // Arrange
                var originalKey = RsaKey.Generate();
                var originalCertificate = (RsaCertificate)originalKey.DeriveCertificate();

                // Act
                var model = SerializationModelConverter.Convert(certificate: originalCertificate);
                var certificate = SerializationModelConverter.ConvertCertificateModel(model: model);

                // Assert
                System.Convert.FromBase64String(model.Hash).SequenceEqual(originalCertificate.Hash.Hash).Should().BeTrue();
                certificate.Hash.Hash.SequenceEqual(originalCertificate.Hash.Hash).Should().BeTrue();
                model.EmbeddedData.Should().BeNull();
                certificate.EmbeddedData.Should().BeNull();
                model.SignerCertificateHash.Should().BeNull();
                model.Signature.Should().BeNull();
                certificate.Signature.Should().BeNull();
            }

            [Test]
            public void WithoutEmbeddedDataButWithSignature_Should_Succeed()
            {
                // Arrange
                var signerKey = RsaKey.Generate();
                var originalKey = RsaKey.Generate(
                    signKeyCallback: hash => (RsaSignature)signerKey.Sign(hash));
                var originalCertificate = (RsaCertificate)originalKey.DeriveCertificate();

                // Act
                var model = SerializationModelConverter.Convert(certificate: originalCertificate);
                var certificate = SerializationModelConverter.ConvertCertificateModel(model: model);

                // Assert
                System.Convert.FromBase64String(model.Hash).SequenceEqual(originalCertificate.Hash.Hash).Should().BeTrue();
                certificate.Hash.Hash.SequenceEqual(originalCertificate.Hash.Hash).Should().BeTrue();
                model.EmbeddedData.Should().BeNull();
                certificate.EmbeddedData.Should().BeNull();
                System.Convert.FromBase64String(model.SignerCertificateHash).SequenceEqual(originalCertificate.Signature.SignerCertificateHash.Hash).Should().BeTrue();
                System.Convert.FromBase64String(model.Signature).SequenceEqual(originalCertificate.Signature.Signature).Should().BeTrue();
                certificate.Signature.SignerCertificateHash.Hash.SequenceEqual(originalCertificate.Signature.SignerCertificateHash.Hash).Should().BeTrue();
                certificate.Signature.Signature.SequenceEqual(originalCertificate.Signature.Signature).Should().BeTrue();
            }

            [Test]
            public void WithEmbeddedDataButWithoutSignature_Should_Succeed()
            {
                // Arrange
                var originalKey = RsaKey.Generate(embeddedData: new byte[] { 0x01, 0x02, 0x03, 0x03 });
                var originalCertificate = (RsaCertificate)originalKey.DeriveCertificate();

                // Act
                var model = SerializationModelConverter.Convert(certificate: originalCertificate);
                var certificate = SerializationModelConverter.ConvertCertificateModel(model: model);

                // Assert
                System.Convert.FromBase64String(model.Hash).SequenceEqual(originalCertificate.Hash.Hash).Should().BeTrue();
                certificate.Hash.Hash.SequenceEqual(originalCertificate.Hash.Hash).Should().BeTrue();
                System.Convert.FromBase64String(model.EmbeddedData).SequenceEqual(originalCertificate.EmbeddedData).Should().BeTrue();
                certificate.EmbeddedData.SequenceEqual(originalCertificate.EmbeddedData).Should().BeTrue();
                model.SignerCertificateHash.Should().BeNull();
                model.Signature.Should().BeNull();
                certificate.Signature.Should().BeNull();
            }

            [Test]
            public void WithEmbeddedDataAndWithSignature_Should_Succeed()
            {
                // Arrange
                var signerKey = RsaKey.Generate();
                var originalKey = RsaKey.Generate(
                    embeddedData: new byte[] { 0x01, 0x02, 0x03, 0x03 },
                    signKeyCallback: hash => (RsaSignature)signerKey.Sign(hash));
                var originalCertificate = (RsaCertificate)originalKey.DeriveCertificate();

                // Act
                var model = SerializationModelConverter.Convert(certificate: originalCertificate);
                var certificate = SerializationModelConverter.ConvertCertificateModel(model: model);

                // Assert
                System.Convert.FromBase64String(model.Hash).SequenceEqual(originalCertificate.Hash.Hash).Should().BeTrue();
                certificate.Hash.Hash.SequenceEqual(originalCertificate.Hash.Hash).Should().BeTrue();
                System.Convert.FromBase64String(model.EmbeddedData).SequenceEqual(originalCertificate.EmbeddedData).Should().BeTrue();
                certificate.EmbeddedData.SequenceEqual(originalCertificate.EmbeddedData).Should().BeTrue();
                System.Convert.FromBase64String(model.SignerCertificateHash).SequenceEqual(originalCertificate.Signature.SignerCertificateHash.Hash).Should().BeTrue();
                System.Convert.FromBase64String(model.Signature).SequenceEqual(originalCertificate.Signature.Signature).Should().BeTrue();
                certificate.Signature.SignerCertificateHash.Hash.SequenceEqual(originalCertificate.Signature.SignerCertificateHash.Hash).Should().BeTrue();
                certificate.Signature.Signature.SequenceEqual(originalCertificate.Signature.Signature).Should().BeTrue();
            }
        }

        public class RsaParameters
        {
            [Test]
            public void RsaSerializationModelInvalid_ShouldThrow_NotSupportedException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<NotSupportedException>(
                    () => SerializationModelConverter.Convert(
                        rsaSerializationModel: new RsaSerializationModel
                        {
                            D = "invalidBase64",
                        }));
            }

            [Test]
            public void RoundtripKey_Should_Succeed()
            {
                // Arrange
                var originalRsaParameters = RSACryptoServiceProvider.Create(RsaKey.KeySize).ExportParameters(true);

                // Act
                var model = SerializationModelConverter.Convert(rsaParameters: originalRsaParameters);
                var rsaParameters = SerializationModelConverter.Convert(rsaSerializationModel: model);

                // Assert
                model.D.Length.Should().BeGreaterThan(0);
                System.Convert.FromBase64String(model.D).SequenceEqual(rsaParameters.D).Should().BeTrue();
                model.DP.Length.Should().BeGreaterThan(0);
                System.Convert.FromBase64String(model.DP).SequenceEqual(rsaParameters.DP).Should().BeTrue();
                model.DQ.Length.Should().BeGreaterThan(0);
                System.Convert.FromBase64String(model.DQ).SequenceEqual(rsaParameters.DQ).Should().BeTrue();
                model.Exponent.Length.Should().BeGreaterThan(0);
                System.Convert.FromBase64String(model.Exponent).SequenceEqual(rsaParameters.Exponent).Should().BeTrue();
                model.InverseQ.Length.Should().BeGreaterThan(0);
                System.Convert.FromBase64String(model.InverseQ).SequenceEqual(rsaParameters.InverseQ).Should().BeTrue();
                model.Modulus.Length.Should().BeGreaterThan(0);
                System.Convert.FromBase64String(model.Modulus).SequenceEqual(rsaParameters.Modulus).Should().BeTrue();
                model.P.Length.Should().BeGreaterThan(0);
                System.Convert.FromBase64String(model.P).SequenceEqual(rsaParameters.P).Should().BeTrue();
                model.Q.Length.Should().BeGreaterThan(0);
                System.Convert.FromBase64String(model.Q).SequenceEqual(rsaParameters.Q).Should().BeTrue();
            }

            [Test]
            public void RoundtripCertificate_Should_Succeed()
            {
                // Arrange
                var originalRsaParameters = RSACryptoServiceProvider.Create(RsaKey.KeySize).ExportParameters(false);

                // Act
                var model = SerializationModelConverter.Convert(rsaParameters: originalRsaParameters);
                var rsaParameters = SerializationModelConverter.Convert(rsaSerializationModel: model);

                // Assert
                model.D.Should().BeNull();
                rsaParameters.D.Should().BeNull();
                model.DP.Should().BeNull();
                rsaParameters.DP.Should().BeNull();
                model.DQ.Should().BeNull();
                rsaParameters.DQ.Should().BeNull();
                System.Convert.FromBase64String(model.Exponent).SequenceEqual(rsaParameters.Exponent).Should().BeTrue();
                model.InverseQ.Should().BeNull();
                rsaParameters.InverseQ.Should().BeNull();
                System.Convert.FromBase64String(model.Modulus).SequenceEqual(rsaParameters.Modulus).Should().BeTrue();
                model.P.Should().BeNull();
                rsaParameters.P.Should().BeNull();
                model.Q.Should().BeNull();
                rsaParameters.Q.Should().BeNull();
            }
        }
    }
}
