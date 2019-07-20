namespace TrustMe
{
	/// <summary>
	/// Represents an exception class for any trust-related issues.
	/// </summary>
	public class TrustException : System.Exception
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="TrustException"/> class.
		/// </summary>
		public TrustException()
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="TrustException"/> class.
		/// </summary>
		/// <param name="message">The exception message.</param>
		public TrustException(string message)
			: base(message)
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="TrustException"/> class.
		/// </summary>
		/// <param name="message">The exception message.</param>
		/// <param name="innerException">The inner exception.</param>
		public TrustException(string message, System.Exception innerException)
			: base(message, innerException)
		{
		}
	}
}