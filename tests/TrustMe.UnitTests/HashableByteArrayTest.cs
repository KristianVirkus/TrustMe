using FluentAssertions;
using NUnit.Framework;
using System;
using System.Linq;

namespace TrustMe.UnitTests
{
    static class HashableByteArrayTest
    {
        public class Constructors
        {
            [Test]
            public void DataNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => new HashableByteArray(data: null));
            }

            [Test]
            public void Constructor_Should_SetProperties()
            {
                // Arrange
                // Act
                var obj = new HashableByteArray(data: ScenarioRsa.DefaultData);

                // Assert
                obj.Data.SequenceEqual(ScenarioRsa.DefaultData).Should().BeTrue();
            }
        }

        public class Computation
        {
            [Test]
            public void SameData_Should_ComputeSameHashValue()
            {
                // Arrange
                // Act
                var obj1 = new HashableByteArray(data: ScenarioRsa.DefaultData);
                var obj2 = new HashableByteArray(data: ScenarioRsa.DefaultData);

                // Assert
                obj1.ComputeHash().Equals(obj2.ComputeHash()).Should().BeTrue();
            }

            [Test]
            public void DifferentData_Should_ComputeDifferentHashValues()
            {
                // Arrange
                // Act
                var obj1 = new HashableByteArray(data: ScenarioRsa.DefaultData);
                var obj2 = new HashableByteArray(data: ScenarioRsa.DefaultEmbeddedData);

                // Assert
                obj1.ComputeHash().Equals(obj2.ComputeHash()).Should().BeFalse();
            }
        }
    }
}
