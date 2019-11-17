namespace TrustMe
{
	/// <summary>
	/// Common interface of all certificate locators.
	/// </summary>
	public interface ICertificateLocator
	{
		/// <summary>
		/// Locates a certificate by its hash.
		/// </summary>
		/// <param name="hash">The certificate hash.</param>
		/// <returns>The certificate or null if none found.</returns>
		/// <exception cref="ArgumentNullException">Thrown if
		///		<paramref name="hash"/> is null.</exception>
		ICertificate Get(IHash hash);
	}

	/// <summary>
	/// Common interface of all generic certificate locators.
	/// </summary>
	/// <typeparam name="TCertificate">The certificate type.</typeparam>
	//public interface ICertificateLocator<TCertificate> : ICertificateLocator
	//{
	//	/// <summary>
	//	/// Locates a certificate by its hash.
	//	/// </summary>
	//	/// <param name="hash">The certificate hash.</param>
	//	/// <returns>The certificate or null if none found.</returns>
	//	/// <exception cref="ArgumentNullException">Thrown if
	//	///		<paramref name="hash"/> is null.</exception>
	//	new TCertificate Get(IHash hash);
	//}
}
