using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace TrustMe
{
    /// <summary>
    /// Represents an RSA signature.
    /// </summary>
    public sealed class RsaSignature : ISignature, IEquatable<ISignature>
    {
        #region ISignature implementation

        /// <summary>
        /// Gets the hash value representing the signer's certificate's hash value
        /// and the signature itself.
        /// </summary>
        public IHash Hash { get; }

        /// <summary>
        /// Gets the signer's certificate's hash.
        /// </summary>
        public IHash SignerCertificateHash { get; }

        /// <summary>
        /// Gets the signature over the public RSA parameters, embedded raw data and
        /// the signer's certificate's hash value.
        /// </summary>
        public IReadOnlyCollection<byte> Signature { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaSignature"/> class.
        /// </summary>
        /// <param name="signerCertificateHash">The signer's certificate's hash.</param>
        /// <param name="signature">The signature data.</param>
        /// <exception cref="ArgumentNullException">Thrown if
        ///		<paramref name="signerCertificateHash"/> or
        ///		<paramref name="signature"/> is null.</exception>
        public RsaSignature(IHash signerCertificateHash, byte[] signature)
        {
            this.SignerCertificateHash = signerCertificateHash ?? throw new ArgumentNullException(nameof(signerCertificateHash));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            this.Signature = Array.AsReadOnly(signature);
            this.Hash = this.computeHash();
        }

        #endregion

        #region IEquatable implementation

        public bool Equals(ISignature other) => this.Hash.Equals(other?.Hash);

        #endregion

        #region Methods

        public override bool Equals(object obj) => this.Hash.Equals((obj as RsaSignature)?.Hash);

        public override int GetHashCode() => this.Hash.GetHashCode();

        #endregion

        #region Private methods

        private IHash computeHash()
        {
            using (var stream = new MemoryStream())
            {
                var signerCertificateHashCountBytes = BitConverter.GetBytes(this.SignerCertificateHash.Hash.Count);
                if (!BitConverter.IsLittleEndian) signerCertificateHashCountBytes = signerCertificateHashCountBytes.Reverse().ToArray();
                stream.Write(signerCertificateHashCountBytes, 0, signerCertificateHashCountBytes.Length);
                stream.Write(this.SignerCertificateHash.Hash.ToArray(), 0, this.SignerCertificateHash.Hash.Count);

                var signatureCountBytes = BitConverter.GetBytes(this.Signature.Count);
                if (!BitConverter.IsLittleEndian) signatureCountBytes = signatureCountBytes.Reverse().ToArray();
                stream.Write(signatureCountBytes, 0, signatureCountBytes.Length);
                stream.Write(this.Signature.ToArray(), 0, this.Signature.Count);

                stream.Position = 0;
                return Sha512Hash.Compute(stream);
            }
        }

        #endregion
    }
}
