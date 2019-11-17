using FluentAssertions;
using NUnit.Framework;
using System;

namespace TrustMe.UnitTests
{
    static class HashableStringTest
    {
        public class Constructors
        {
            [Test]
            public void DataNull_ShouldThrow_ArgumentNullException()
            {
                // Arrange
                // Act & Assert
                Assert.Throws<ArgumentNullException>(() => new HashableString(data: null));
            }

            [Test]
            public void DataEmpty_Should_SetProperties()
            {
                // Arrange
                // Act
                var obj = new HashableString(data: "");

                // Assert
                obj.Data.Should().BeEmpty();
            }

            [Test]
            public void Constructor_Should_SetProperties()
            {
                // Arrange
                // Act
                var obj = new HashableString(data: "test data");

                // Assert
                obj.Data.Should().Be("test data");
            }
        }

        public class Computation
        {
            [Test]
            public void SameData_Should_ComputeSameHashValue()
            {
                // Arrange
                // Act
                var obj1 = new HashableString(data: "test data");
                var obj2 = new HashableString(data: "test data");

                // Assert
                obj1.ComputeHash().Equals(obj2.ComputeHash()).Should().BeTrue();
            }

            [Test]
            public void DifferentData_Should_ComputeDifferentHashValues()
            {
                // Arrange
                // Act
                var obj1 = new HashableString(data: "test data");
                var obj2 = new HashableString(data: "other data");

                // Assert
                obj1.ComputeHash().Equals(obj2.ComputeHash()).Should().BeFalse();
            }

            [Test]
            public void EmptyData_Should_Succeed()
            {
                // Arrange
                // Act
                // Assert
                new HashableString(data: "test data").ComputeHash();
            }
        }
    }
}
