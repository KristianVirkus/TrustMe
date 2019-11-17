using System;
using System.Collections.Generic;
using System.Linq;

namespace TrustMe
{
    /// <summary>
    /// Implements a hashable byte array.
    /// </summary>
    public class HashableByteArray : IHashable
    {
        /// <summary>
        /// Gets the byte data.
        /// </summary>
        public IReadOnlyCollection<byte> Data { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HashableByteArray"/> class.
        /// </summary>
        /// <param name="data">The byte data.</param>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="data"/> is null.</exception>
        public HashableByteArray(byte[] data)
        {
            this.Data = data ?? throw new ArgumentNullException(nameof(data));
        }

        /// <summary>
        /// Computes the hash value of the byte data.
        /// </summary>
        /// <returns>The hash value.</returns>
        public IHash ComputeHash() => Sha512Hash.Compute(this.Data.ToArray());
    }
}
