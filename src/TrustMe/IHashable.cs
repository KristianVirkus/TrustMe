namespace TrustMe
{
	/// <summary>
	/// Common interface of all hashable objects.
	/// </summary>
	public interface IHashable
	{
		/// <summary>
		/// Computes the hash of the object.
		/// </summary>
		/// <remarks>The selection of the hashing algorithm is up to the programmer.</remarks>
		/// <returns>The hash.</returns>
		IHash ComputeHash();
	}
}
