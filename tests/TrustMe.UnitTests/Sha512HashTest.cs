using FluentAssertions;
using NUnit.Framework;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TrustMe.UnitTests
{
    public class Sha512HashTest
    {
        public class Constructors
        {
            [Test]
            public void ConstructorHashNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => new Sha512Hash(null));
            }

            [Test]
            public void ConstructorHashInvalidLength_Should_ThrowTrustException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<TrustException>(() => new Sha512Hash(Array.AsReadOnly(new byte[] { 0x01, 0x02, 0x03 })));
            }

            [Test]
            public void Constructor_Should_SetProperties()
            {
                // Arrange
                var hash = Sha512Hash.Compute(new byte[64]);

                // Act
                var obj = new Sha512Hash(hash.Hash);

                // Assert
                obj.Hash.SequenceEqual(hash.Hash).Should().BeTrue();
                obj.Name.Should().Be(HashAlgorithmName.SHA512);
            }
        }

        public class Creation
        {
            [Test]
            public void CreateInstance_Should_CreateInstance()
            {
                // Arrange
                // Act
                var obj = new Sha512Hash(hash: new byte[64]).CreateAlgorithm();

                // Assert
                obj.Should().BeAssignableTo<SHA512>();
            }
        }

        public class Compute
        {
            [Test]
            public void FromArrayNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => Sha512Hash.Compute((byte[])null));
            }

            [Test]
            public void FromEmptyArray_Should_Succeed()
            {
                // Arrange
                // Act
                // Assert
                Sha512Hash.Compute(new byte[0]).Hash
                    .SequenceEqual(Sha512Hash.Compute(new byte[0]).Hash).Should().BeTrue();
            }

            [Test]
            public void FromArrayWithInputBlockSizeLength_Should_Succeed()
            {
                // Arrange
                int inputBlockSize;
                using (var sha512 = SHA512Managed.Create()) inputBlockSize = sha512.InputBlockSize;

                // Act
                // Assert
                Sha512Hash.Compute(new byte[inputBlockSize]).Hash
                    .SequenceEqual(Sha512Hash.Compute(new byte[inputBlockSize]).Hash).Should().BeTrue();
            }

            [Test]
            public void FromArray_Should_Succeed()
            {
                // Arrange
                // Act
                var obj = Sha512Hash.Compute(Encoding.UTF8.GetBytes("test"));
                // Assert
                obj.Hash.SequenceEqual(Sha512Hash.Compute(Encoding.UTF8.GetBytes("test")).Hash).Should().BeTrue();
                obj.Name.Should().Be(HashAlgorithmName.SHA512);
            }

            [Test]
            public void FromStreamNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => Sha512Hash.Compute((Stream)null));
            }

            [Test]
            public void FromEmptyStream_Should_Succeed()
            {
                // Arrange
                IHash hash1 = null;
                IHash hash2 = null;

                // Act
                using (var stream = new MemoryStream(new byte[0]))
                {
                    hash1 = Sha512Hash.Compute(stream);
                }

                using (var stream = new MemoryStream(new byte[0]))
                {
                    hash2 = Sha512Hash.Compute(stream);
                }

                // Assert
                hash1.Hash.SequenceEqual(hash2.Hash).Should().BeTrue();
            }

            [Test]
            public void Stream_Should_Succeed()
            {
                // Arrange
                var data = Encoding.UTF8.GetBytes("test");
                IHash hash1 = null;
                IHash hash2 = null;

                // Act
                using (var stream = new MemoryStream(data))
                {
                    hash1 = Sha512Hash.Compute(stream);
                }

                using (var stream = new MemoryStream(data))
                {
                    hash2 = Sha512Hash.Compute(stream);
                }

                // Assert
                hash1.Hash.SequenceEqual(hash2.Hash).Should().BeTrue();
                hash1.Name.Should().Be(HashAlgorithmName.SHA512);
            }

            [Test]
            public void FromArrayAndStream_Should_BeEqual()
            {
                // Arrange
                var data = Encoding.UTF8.GetBytes("test");
                using (var stream = new MemoryStream(data))
                {

                    // Act
                    var arrayHash = Sha512Hash.Compute(data);
                    var streamHash = Sha512Hash.Compute(stream);

                    // Assert
                    arrayHash.Hash.SequenceEqual(streamHash.Hash).Should().BeTrue();
                }
            }
        }

        public class Equality
        {
            [Test]
            public void SameHashes_ShouldReturn_True()
            {
                // Arrange
                var hash1 = Sha512Hash.Compute(Encoding.UTF8.GetBytes("test"));
                var hash2 = Sha512Hash.Compute(Encoding.UTF8.GetBytes("test"));

                // Act
                // Assert
                hash1.Equals((IHash)hash2).Should().BeTrue();
                hash1.Equals((object)hash2).Should().BeTrue();
            }

            [Test]
            public void DifferentHashes_ShouldReturn_False()
            {
                // Arrange
                var hash1 = Sha512Hash.Compute(Encoding.UTF8.GetBytes("test"));
                var hash2 = Sha512Hash.Compute(Encoding.UTF8.GetBytes("TEST"));

                // Act
                // Assert
                hash1.Equals((IHash)hash2).Should().BeFalse();
                hash1.Equals((object)hash2).Should().BeFalse();
            }
        }

        public class GetHashCodeMethod
        {
            [Test]
            public void SameHashes_ShouldReturn_SameHashCodes()
            {
                // Arrange
                var hash1 = Sha512Hash.Compute(Encoding.UTF8.GetBytes("test"));
                var hash2 = Sha512Hash.Compute(Encoding.UTF8.GetBytes("test"));

                // Act
                // Assert
                hash1.GetHashCode().Should().Be(hash2.GetHashCode());
            }

            [Test]
            public void DifferentHashes_ShouldReturn_DifferentHashCodes()
            {
                // Arrange
                var hash1 = Sha512Hash.Compute(Encoding.UTF8.GetBytes("test"));
                var hash2 = Sha512Hash.Compute(Encoding.UTF8.GetBytes("TEST"));

                // Act
                // Assert
                hash1.GetHashCode().Should().NotBe(hash2.GetHashCode());
            }
        }
    }
}