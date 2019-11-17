namespace TrustMe
{
    /// <summary>
    /// Represents an exception class for any trust-related issues.
    /// </summary>
    public class TrustException : System.Exception
    {
        const string DefaultMessage = "An error occurred proving or verifying the trustworthiness of your data.";

        /// <summary>
        /// Initializes a new instance of the <see cref="TrustException"/> class.
        /// </summary>
        public TrustException()
            : this(message: DefaultMessage)
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