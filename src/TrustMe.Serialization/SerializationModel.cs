namespace TrustMe.Serialization
{
    /// <summary>
    /// Represents a key/certificate serialization model.
    /// </summary>
    public class SerializationModel
    {
        /// <summary>
        /// Gets or sets the hash over the RSA parameters and the
        /// embedded data as Base64 string. The signature information
        /// is not included in the hash.
        /// </summary>
        public string Hash { get; set; }

        /// <summary>
        /// Gets or sets the embedded data as Base64 string.
        /// </summary>
        public string EmbeddedData { get; set; }

        /// <summary>
        /// Gets or sets the cryptographic RSA parameters.
        /// </summary>
        public RsaSerializationModel Parameters { get; set; }

        /// <summary>
        /// Gets whether this model represents a key (true)
        /// or a certificate (false.)
        /// </summary>
        public bool IsKey => this.Parameters?.D != null;

        /// <summary>
        /// Gets or sets the signer certificate's hash as Base64 string.
        /// </summary>
        public string SignerCertificateHash { get; set; }

        /// <summary>
        /// Gets or sets the signature as Base64 string.
        /// </summary>
        public string Signature { get; set; }
    }
}
