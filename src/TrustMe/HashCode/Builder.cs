using System;
using System.Collections.Generic;
using System.Linq;

namespace HashCode
{
	/// <summary>
	/// Implements the builder design pattern for computing hash codes for CLR objects.
	/// </summary>
	public class Builder
	{
		const int NullReferenceSubstitute = 1070002057;
		const int NotNullReferenceSubstitute = 2090019947;

		Computer computer = new Computer();

		/// <summary>
		/// Gets or sets whether to include information about added null object references.
		/// </summary>
		public bool AreNullsIncluded { get; set; } = true;

		/// <summary>
		/// Builds the hash code from previous additions to this instance via
		/// the various <c>Add</c> methods.
		/// </summary>
		/// <returns>The hash code.</returns>
		public int Build() => this.computer.ToHashCode();

		/// <summary>
		/// Adds another <paramref name="item"/> to include in the hash code computation.
		/// </summary>
		/// <param name="item">The object to add.</param>
		/// <param name="equalityComparer">The equality comparer instance to use for computing
		///		the hash code of the <paramref name="item"/>.</param>
		/// <returns>The same <see cref="Builder"/> instance to apply the
		///		builder design pattern.</returns>
		public Builder Add<T>(T item, IEqualityComparer<T> equalityComparer = null)
		{
			if ((item != null) || (this.AreNullsIncluded))
			{
				if (this.AreNullsIncluded)
					this.computer.Add(item == null ? NullReferenceSubstitute : NotNullReferenceSubstitute);
				this.computer.Add(item, equalityComparer);
			}

			return this;
		}

		/// <summary>
		/// Adds multiple <paramref name="items"/> to include in the hash code computation.
		/// </summary>
		/// <typeparam name="T">The item type.</typeparam>
		/// <param name="items">The items to add.</param>
		/// <returns>The same <see cref="Builder"/> instance to apply the
		///		builder design pattern.</returns>
		/// <exception cref="ArgumentNullException">Thrown if
		///		<paramref name="items"/> is null.</exception>
		public Builder Add<T>(params T[] items) => this.Add((IEqualityComparer<T>)null, items);

		/// <summary>
		/// Adds multiple <paramref name="items"/> to include in the hash code computation.
		/// </summary>
		/// <typeparam name="T">The item type.</typeparam>
		/// <param name="equalityComparer">The equality comparer instance to use for computing
		///		the hash code of the <paramref name="items"/>.</param>
		/// <param name="items">The items to add.</param>
		/// <returns>The same <see cref="Builder"/> instance to apply the
		///		builder design pattern.</returns>
		/// <exception cref="ArgumentNullException">Thrown if
		///		<paramref name="items"/> is null.</exception>
		public Builder Add<T>(IEqualityComparer<T> equalityComparer, params T[] items)
		{
			if (items == null) throw new ArgumentNullException(nameof(items));
			if (!this.AreNullsIncluded) items = items.Where(i => i != null).ToArray();
			var itemNo = 0;
			foreach (var item in items)
			{
				this.computer.Add(++itemNo);
				if (this.AreNullsIncluded)
					this.computer.Add(item == null ? NullReferenceSubstitute : NotNullReferenceSubstitute);
				this.computer.Add(item, equalityComparer);
			}

			return this;
		}

		/// <summary>
		/// Adds multiple <paramref name="items"/> to include in the hash code computation with
		/// ordering beforehand. This way, the order of the members of the <paramref name="items"/>
		/// argument is irrelevant.
		/// </summary>
		/// <typeparam name="T">The item type.</typeparam>
		/// <param name="items">The items to add.</param>
		/// <returns>The same <see cref="Builder"/> instance to apply the
		///		builder design pattern.</returns>
		/// <exception cref="ArgumentNullException">Thrown if
		///		<paramref name="items"/> is null.</exception>
		public Builder AddIgnoreOrder<T>(params T[] items) => this.AddIgnoreOrder((IComparer<T>)null, items);

		/// <summary>
		/// Adds multiple <paramref name="items"/> to include in the hash code computation with
		/// ordering beforehand. This way, the order of the members of the <paramref name="items"/>
		/// argument is irrelevant.
		/// </summary>
		/// <typeparam name="T">The item type.</typeparam>
		/// <param name="comparer">The comparer instance to use for ordering the items beforehand.</param>
		/// <param name="items">The items to add.</param>
		/// <returns>The same <see cref="Builder"/> instance to apply the
		///		builder design pattern.</returns>
		/// <exception cref="ArgumentNullException">Thrown if
		///		<paramref name="items"/> is null.</exception>
		public Builder AddIgnoreOrder<T>(IComparer<T> comparer, params T[] items)
			=> this.AddIgnoreOrder((IEqualityComparer<T>)null, comparer, items);

		/// <summary>
		/// Adds multiple <paramref name="items"/> to include in the hash code computation with
		/// ordering beforehand. This way, the order of the members of the <paramref name="items"/>
		/// argument is irrelevant. A specific <paramref name="equalityComparer"/> is used.
		/// </summary>
		/// <typeparam name="T">The item type.</typeparam>
		/// <param name="equalityComparer">The equality comparer instance to use for computing
		///		the hash code of the <paramref name="items"/>.</param>
		/// <param name="comparer">The comparer instance to use for ordering the items beforehand.</param>
		/// <param name="items">The items to add.</param>
		/// <returns>The same <see cref="Builder"/> instance to apply the
		///		builder design pattern.</returns>
		/// <exception cref="ArgumentNullException">Thrown if
		///		<paramref name="items"/> is null.</exception>
		public Builder AddIgnoreOrder<T>(IEqualityComparer<T> equalityComparer, IComparer<T> comparer, params T[] items)
		{
			var itemsList = new List<T>(items);
			itemsList.Sort(comparer);
			this.Add<T>(equalityComparer, (T[])itemsList.ToArray());

			return this;
		}
	}
}
