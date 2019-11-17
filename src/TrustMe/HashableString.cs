using System;
using System.Text;

namespace TrustMe
{
    /// <summary>
    /// Implements a hashable string.
    /// </summary>
    public class HashableString : IHashable
    {
        /// <summary>
        /// Gets the string.
        /// </summary>
        public string Data { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HashableString"/> class.
        /// </summary>
        /// <param name="data">The string.</param>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="data"/> is null.</exception>
        public HashableString(string data)
        {
            this.Data = data ?? throw new ArgumentNullException(nameof(data));
        }

        /// <summary>
        /// Computes the hash value of the byte data.
        /// </summary>
        /// <returns>The hash value.</returns>
        public IHash ComputeHash() => Sha512Hash.Compute(Encoding.ASCII.GetBytes(this.Data));
    }
}
