using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace TrustMe
{
    /// <summary>
    /// Implements a SHA512 hash.
    /// </summary>
    public class Sha512Hash : IHash
    {
        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="Sha512Hash"/> class.
        /// </summary>
        /// <param name="hash">The SHA512 hash.</param>
        public Sha512Hash(IReadOnlyCollection<byte> hash)
        {
            this.Hash = hash ?? throw new ArgumentNullException(nameof(hash));
            if (hash.Count != 64) throw new TrustException("Invalid SHA512 hash length.");
        }

        #endregion

        #region IHash implementation

        /// <summary>
        /// Gets the hash value.
        /// </summary>
        public IReadOnlyCollection<byte> Hash { get; }

        /// <summary>
        /// Gets the hash algorithm name.
        /// </summary>
        public HashAlgorithmName Name => HashAlgorithmName.SHA512;

        /// <summary>
        /// Creates a new instance of the same hash algorithm used to
        /// derive hash value represented by this instance.
        /// </summary>
        /// <returns>The instance.</returns>
        public HashAlgorithm CreateAlgorithm() => SHA512Managed.Create();

        /// <summary>
        /// Checks whether this instance's hash value is equal to
        /// a second one.
        /// </summary>
        /// <param name="other">The other hash value.</param>
        /// <returns>true if both hash values are equal, false otherwise.</returns>
        public bool Equals(IHash other)
            => ((other is Sha512Hash sha512) && (this.Hash.SequenceEqual(sha512.Hash)));

        /// <summary>
        /// Checks whether this instance's hash value is equal to
        /// a second one.
        /// </summary>
        /// <param name="other">The other hash value.</param>
        /// <returns>true if both hash values are equal, false otherwise.</returns>
        public override bool Equals(object obj) => this.Equals(obj as IHash);

        /// <summary>
        /// Derives the Dotnet hash code from this instance's hash value for
        /// comparison purposes. This is not cryptographically safe.
        /// </summary>
        /// <returns>The Dotnet hash code.</returns>
        public override int GetHashCode() => new HashCode.Builder().Add(this.Hash.ToArray()).Build();

        #endregion

        #region Methods

        /// <summary>
        /// Computes the SHA512 hash.
        /// </summary>
        /// <remarks>
        /// Adopted from: https://docs.microsoft.com/de-de/dotnet/api/system.security.cryptography.hashalgorithm.transformblock?view=netstandard-2.0#System_Security_Cryptography_HashAlgorithm_TransformBlock_System_Byte___System_Int32_System_Int32_System_Byte___System_Int32_
        /// </remarks>
        /// <param name="data">The data to compute the hash value from.</param>
        /// <returns>The hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="data"/> is null.</exception>
        ///	<exception cref="ArgumentException">Thrown if
        ///		<paramref name="data"/> is longer than <c>Int32.MaxValue</c>.</exception>
        public static IHash Compute(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.LongLength > Int32.MaxValue) throw new ArgumentException("Too much data.");

            using (SHA512Managed sha512 = new SHA512Managed())
            {
                return new Sha512Hash(Array.AsReadOnly(sha512.ComputeHash(data)));
            }
        }

        /// <summary>
        /// Computes the SHA512 hash.
        /// </summary>
        /// <param name="stream">The stream containing the data to compute the
        ///		hash value from.</param>
        /// <returns>The hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="stream"/> is null.</exception>
        public static IHash Compute(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            using (SHA512Managed sha512 = new SHA512Managed())
            {
                var buffer = new byte[sha512.InputBlockSize];
                var len = 0;
                do
                {
                    len = stream.Read(buffer, 0, buffer.Length);
                    if (len == buffer.Length)
                        sha512.TransformBlock(buffer, 0, len, buffer, 0);
                } while (len > 0);

                sha512.TransformFinalBlock(buffer, 0, len);
                return new Sha512Hash(Array.AsReadOnly(sha512.Hash));
            }
        }

        #endregion
    }
}
