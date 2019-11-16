using FluentAssertions;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace TrustMe.UnitTests
{
    class TrustExceptionTest
    {
        [Test]
        public void DefaultConstructor_Should_Succeed()
        {
            // Arrange
            // Act
            var obj = new TrustException();

            // Assert
            obj.Message.Should().NotBeNull();
            obj.InnerException.Should().BeNull();
        }

        [Test]
        public void ConstructorWithMessage_Should_SetProperties()
        {
            // Arrange
            // Act
            var obj = new TrustException(message: "test");

            // Assert
            obj.Message.Should().Be("test");
            obj.InnerException.Should().BeNull();
        }

        [Test]
        public void ConstructorWithMessageAndInnerException_Should_SetProperties()
        {
            // Arrange
            var innerException = new FormatException();

            // Act
            var obj = new TrustException(message: "test", innerException: innerException);

            // Assert
            obj.Message.Should().Be("test");
            obj.InnerException.Should().BeSameAs(innerException);
        }
    }
}
