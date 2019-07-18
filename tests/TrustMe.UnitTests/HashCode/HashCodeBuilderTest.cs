using FluentAssertions;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;

namespace TrustMe.HashCode.UnitTests
{
	class HashCodeBuilderTest
	{
		public class Add
		{
			public class Single
			{
				[Test]
				public void AreNullsIncluded_Should_DefaultToTrue()
				{
					// Arrange
					// Act
					var builder = new global::HashCode.Builder();

					// Assert
					builder.AreNullsIncluded.Should().BeTrue();
				}

				[Test]
				public void ItemAndNullWhileIncludingNulls_Should_ComputeDifferentHashCodeFromItemAndNullWhlieExcludingNulls()
				{
					// Arrange
					var obj = "test";
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = true };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = false };

					// Act
					builder1.Add(obj);
					builder1.Add((object)null);
					builder2.Add(obj);
					builder2.Add((object)null);

					// Assert
					builder1.Build().Should().NotBe(builder2.Build());
				}

				[Test]
				public void SameItem_Should_ComputeSameHashCode()
				{
					// Arrange
					var obj = "test";
					var builder1 = new global::HashCode.Builder();
					var builder2 = new global::HashCode.Builder();

					// Act
					builder1.Add(obj);
					builder2.Add(obj);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}

				[Test]
				public void NullWhileIncludingNulls_Should_ComputeAlwaysTheSameHashCode()
				{
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = true };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = true };

					// Act
					builder1.Add((object)null);
					builder2.Add((object)null);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}

				[Test]
				public void NullWhileExcludingNulls_Should_ComputeAlwaysTheSameHashCode()
				{
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = false };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = false };

					// Act
					builder1.Add((object)null);
					builder2.Add((object)null);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}

				[Test]
				public void NullWhileIncludingNulls_Should_BeDifferentFromNullWhileExcludingNulls()
				{
					// Arrange
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = true };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = false };

					// Act
					builder1.Add((object)null);
					builder2.Add((object)null);

					// Assert
					builder1.Build().Should().NotBe(builder2.Build());
				}

				[Test]
				public void WhileIncludingNullsAddNullAndNotNullItem_Should_ComputeDifferentHashCodeWithReversedItemOrder()
				{
					// Arrange
					var obj = "test";
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = true };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = true };

					// Act
					builder1.Add((object)null);
					builder1.Add(obj);
					builder2.Add(obj);
					builder2.Add((object)null);

					// Assert
					builder1.Build().Should().NotBe(builder2.Build());
				}

				[Test]
				public void WhileExcludingNullsAddNullAndNotNullItem_Should_ComputeSameHashCodeWithReversedItemOrder()
				{
					// Arrange
					var obj = "test";
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = false };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = false };

					// Act
					builder1.Add((object)null);
					builder1.Add(obj);
					builder2.Add(obj);
					builder2.Add((object)null);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}

				[Test]
				public void WithEqualityComparerAlwaysReturningTheSameHashCode_Should_ComputeTheSameHashCodeForDifferentItems()
				{
					// Arrange
					var builder1 = new global::HashCode.Builder();
					var builder2 = new global::HashCode.Builder();
					var equalityComparer = new CallbackEqualityComparer<string>((x, y) => true, (obj) => 1337);

					// Act
					builder1.Add("test", equalityComparer);
					builder2.Add("item", equalityComparer);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}
			}

			public class Multiple
			{
				[Test]
				public void NullItems_ShouldThrow_ArgumentNullException()
				{
					// Arrange
					var builder = new global::HashCode.Builder();

					// Act & Assert
					Assert.Throws<ArgumentNullException>(() => builder.Add<object>((object[])null));
				}

				[Test]
				public void ItemAndNullWhileIncludingNulls_Should_ComputeDifferentHashCodeFromItemAndNullWhlieExcludingNulls()
				{
					// Arrange
					var obj = "test";
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = true };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = false };

					// Act
					builder1.Add(obj, (object)null);
					builder2.Add(obj, (object)null);

					// Assert
					builder1.Build().Should().NotBe(builder2.Build());
				}

				[Test]
				public void SameItems_Should_ComputeSameHashCode()
				{
					// Arrange
					var objs = new[] { "test", "item" };
					var builder1 = new global::HashCode.Builder();
					var builder2 = new global::HashCode.Builder();

					// Act
					builder1.Add(objs);
					builder2.Add(objs);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}

				[Test]
				public void SameItemsInDifferentOrder_Should_ComputeDifferentHashCodes()
				{
					// Arrange
					var objs = new[] { "test", "item" };
					var builder1 = new global::HashCode.Builder();
					var builder2 = new global::HashCode.Builder();

					// Act
					builder1.Add(objs);
					builder2.Add(objs.Reverse());

					// Assert
					builder1.Build().Should().NotBe(builder2.Build());
				}

				[Test]
				public void WhileIncludingNullsAddNullAndNotNullItem_Should_ComputeDifferentHashCodeWithReversedItemOrder()
				{
					// Arrange
					var obj = "test";
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = true };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = true };

					// Act
					builder1.Add((object)null, obj);
					builder2.Add(obj, (object)null);

					// Assert
					builder1.Build().Should().NotBe(builder2.Build());
				}

				[Test]
				public void WhileExcludingNullsAddNullAndNotNullItem_Should_ComputeSameHashCodeWithReversedItemOrder()
				{
					// Arrange
					var obj = "test";
					var builder1 = new global::HashCode.Builder() { AreNullsIncluded = false };
					var builder2 = new global::HashCode.Builder() { AreNullsIncluded = false };

					// Act
					builder1.Add((object)null, obj);
					builder2.Add(obj, (object)null);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}

				[Test]
				public void WithEqualityComparerAlwaysReturningTheSameHashCode_Should_ComputeTheSameHashCodeForDifferentItems()
				{
					// Arrange
					var builder1 = new global::HashCode.Builder();
					var builder2 = new global::HashCode.Builder();
					var equalityComparer = new CallbackEqualityComparer<string>((x, y) => true, (obj) => 1337);

					// Act
					builder1.Add(equalityComparer, "test", "1");
					builder2.Add(equalityComparer, "item", "a");

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}
			}

			public class MultipleIgnoreOrder
			{
				[Test]
				public void ComparerNull_Should_ApplyDefaultOrdering()
				{
					var builder1 = new global::HashCode.Builder();
					var builder2 = new global::HashCode.Builder();

					// Act
					builder1.AddIgnoreOrder(1, 2);
					builder2.AddIgnoreOrder(2, 1);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}

				[Test]
				public void WithComparer_Should_ComputeSameHashCodeAsWithExplicitOrderedItems()
				{
					var builder1 = new global::HashCode.Builder();
					var builder2 = new global::HashCode.Builder();
					var comparer = new CallbackComparer<int>((x, y) => (x == y ? 0 : (x < y) ? -1 : +1));

					// Act
					builder1.AddIgnoreOrder(comparer, 2, 1);
					builder2.Add(1, 2);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}

				[Test]
				public void WithEqualityComparerReturningTheArgumentIntegerValuesModulusByTwoAndAndWithComparer_Should_ComputeTheSameHashCode()
				{
					var builder1 = new global::HashCode.Builder();
					var builder2 = new global::HashCode.Builder();
					var equalityComparer = new CallbackEqualityComparer<int>((x, y) => true, (obj) => obj % 2);
					var comparer = new CallbackComparer<int>((x, y) => (x == y ? 0 : (x < y) ? -1 : +1));

					// Act
					builder1.AddIgnoreOrder(equalityComparer, comparer, 4, 3);
					builder2.Add(equalityComparer, 1, 2);

					// Assert
					builder1.Build().Should().Be(builder2.Build());
				}
			}
		}

		public class BuilderPattern
		{
			[Test]
			public void BuilderPattern_Should_Succeed()
			{
				// Arrange
				var builder1 = new global::HashCode.Builder();
				var builder2 = new global::HashCode.Builder();

				// Act
				var hashCode1 = builder1
					.Add(1)
					.Add(2)
					.Add(3, 4)
					.AddIgnoreOrder(6, 5)
					.Build();

				builder2.Add(1);
				builder2.Add(2);
				builder2.Add(3, 4);
				builder2.Add(5, 6);

				// Assert
				hashCode1.Should().Be(builder2.Build());
			}
		}

		class CallbackEqualityComparer<T> : IEqualityComparer<T>
		{
			private readonly Func<T, T, bool> equalsCallback;
			private readonly Func<T, int> getHashCodeCallback;

			public CallbackEqualityComparer(Func<T, T, bool> equalsCallback, Func<T, int> getHashCodeCallback)
			{
				this.equalsCallback = equalsCallback;
				this.getHashCodeCallback = getHashCodeCallback;
			}

			public bool Equals(T x, T y) => this.equalsCallback(x, y);
			public int GetHashCode(T obj) => this.getHashCodeCallback(obj);
		}

		class CallbackComparer<T> : IComparer<T>
		{
			private readonly Func<T, T, int> compareCallback;

			public CallbackComparer(Func<T, T, int> compareCallback)
			{
				this.compareCallback = compareCallback;
			}

			public int Compare(T x, T y) => this.compareCallback(x, y);
		}
	}
}
