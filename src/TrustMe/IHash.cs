using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace TrustMe
{
    /// <summary>
    /// Common interface of all hashed data.
    /// </summary>
    public interface IHash : IEquatable<IHash>
    {
        /// <summary>
        /// Gets the hash value.
        /// </summary>
        IReadOnlyCollection<byte> Hash { get; }

        /// <summary>
        /// Gets the hash algorithm name.
        /// </summary>
        HashAlgorithmName Name { get; }

        /// <summary>
        /// Creates a new instance of the same hash algorithm used to
        /// derive hash value represented by this instance.
        /// </summary>
        /// <returns>The instance.</returns>
        HashAlgorithm CreateAlgorithm();
    }
}
