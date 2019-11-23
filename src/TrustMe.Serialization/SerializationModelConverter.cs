using System;
using System.Linq;
using System.Security.Cryptography;

namespace TrustMe.Serialization
{
    /// <summary>
    /// Implements a converter for the serialization model.
    /// </summary>
    static class SerializationModelConverter
    {
        /// <summary>
        /// Creates a cyptographic RSA key from this model.
        /// </summary>
        /// <param name="model">The serialization model.</param>
        /// <returns>The cryptographic RSA key.</returns>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="model"/> is null.</exception>
        /// <exception cref="NotSupportedException">Thrown, if
        ///     this model is either incomplete, invalid or does
        ///     not include a valid RSA key.</exception>
        public static RsaKey ConvertKeyModel(SerializationModel model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));
            if (!model.IsKey) throw new NotSupportedException("The model contains a certificate.");

            if (model.SignerCertificateHash == null ^ model.Signature == null)
                throw new NotSupportedException("The signature is incomplete.");

            try
            {
                if (model.Signature == null)
                    return new RsaKey(
                        parameters: Convert(model.Parameters),
                        embeddedData: string.IsNullOrEmpty(model.EmbeddedData) ? null : System.Convert.FromBase64String(model.EmbeddedData));
                else
                    return new RsaKey(
                        parameters: Convert(model.Parameters),
                        embeddedData: string.IsNullOrEmpty(model.EmbeddedData) ? null : System.Convert.FromBase64String(model.EmbeddedData),
                        signature: new RsaSignature(
                            signerCertificateHash: new Sha512Hash(System.Convert.FromBase64String(model.SignerCertificateHash)),
                            signature: System.Convert.FromBase64String(model.Signature)));
            }
            catch (Exception ex)
            {
                throw new NotSupportedException("The model is invalid or not supported.", ex);
            }
        }

        /// <summary>
        /// Creates a cryptographic RSA certificate from this model.
        /// </summary>
        /// <param name="model">The serialization model.</param>
        /// <returns>The cryptographic RSA certificate.</returns>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="model"/> is null.</exception>
        /// <exception cref="NotSupportedException">Thrown, if
        ///     this model is either incomplete, invalid or does
        ///     either not include a valid RSA certificate or
        ///     includes an RSA key instead.</exception>
        public static RsaCertificate ConvertCertificateModel(SerializationModel model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));
            if (model.IsKey) throw new NotSupportedException("The model contains a key.");

            if (model.SignerCertificateHash == null ^ model.Signature == null)
                throw new NotSupportedException("The signature is incomplete.");

            try
            {
                if (model.Signature == null)
                    return new RsaCertificate(
                        parameters: Convert(model.Parameters),
                        embeddedData: string.IsNullOrEmpty(model.EmbeddedData) ? null : System.Convert.FromBase64String(model.EmbeddedData));
                else
                    return new RsaCertificate(
                        parameters: Convert(model.Parameters),
                        embeddedData: string.IsNullOrEmpty(model.EmbeddedData) ? null : System.Convert.FromBase64String(model.EmbeddedData),
                        signature: new RsaSignature(
                            signerCertificateHash: new Sha512Hash(System.Convert.FromBase64String(model.SignerCertificateHash)),
                            signature: System.Convert.FromBase64String(model.Signature)));
            }
            catch (Exception ex)
            {
                throw new NotSupportedException("The model is invalid or not supported.", ex);
            }
        }

        /// <summary>
        /// Converts a cryptographic RSA key to a serialization model instance.
        /// </summary>
        /// <param name="key">The cryptographic RSA key.</param>
        /// <returns>The serialization model.</returns>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="key"/> is null.</exception>
        public static SerializationModel Convert(RsaKey key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            var rsaParameters = key.CreateRsa().ExportParameters(true);
            return new SerializationModel
            {
                Hash = System.Convert.ToBase64String(key.Hash.Hash.ToArray()),
                Parameters = new RsaSerializationModel
                {
                    D = System.Convert.ToBase64String(rsaParameters.D),
                    DP = System.Convert.ToBase64String(rsaParameters.DP),
                    DQ = System.Convert.ToBase64String(rsaParameters.DQ),
                    Exponent = System.Convert.ToBase64String(rsaParameters.Exponent),
                    InverseQ = System.Convert.ToBase64String(rsaParameters.InverseQ),
                    Modulus = System.Convert.ToBase64String(rsaParameters.Modulus),
                    P = System.Convert.ToBase64String(rsaParameters.P),
                    Q = System.Convert.ToBase64String(rsaParameters.Q),
                },
                EmbeddedData = key.EmbeddedData == null ? null : System.Convert.ToBase64String(key.EmbeddedData.ToArray()),
                SignerCertificateHash = key.Signature == null ? null : System.Convert.ToBase64String(key.Signature.SignerCertificateHash.Hash.ToArray()),
                Signature = key.Signature == null ? null : System.Convert.ToBase64String(key.Signature.Signature.ToArray()),
            };
        }

        /// <summary>
        /// Converts a cryptographic RSA certificate to a serialization model instance.
        /// </summary>
        /// <param name="certificate">The cryptographic RSA certificate.</param>
        /// <returns>The serialization model.</returns>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="certificate"/> is null.</exception>
        public static SerializationModel Convert(RsaCertificate certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            var rsaParameters = certificate.CreateRsa().ExportParameters(false);
            return new SerializationModel
            {
                Hash = System.Convert.ToBase64String(certificate.Hash.Hash.ToArray()),
                Parameters = new RsaSerializationModel
                {
                    Exponent = System.Convert.ToBase64String(rsaParameters.Exponent),
                    Modulus = System.Convert.ToBase64String(rsaParameters.Modulus),
                },
                EmbeddedData = certificate.EmbeddedData == null ? null : System.Convert.ToBase64String(certificate.EmbeddedData.ToArray()),
                SignerCertificateHash = certificate.Signature == null ? null : System.Convert.ToBase64String(certificate.Signature.SignerCertificateHash.Hash.ToArray()),
                Signature = certificate.Signature == null ? null : System.Convert.ToBase64String(certificate.Signature.Signature.ToArray()),
            };
        }

        /// <summary>
        /// Converts a serialization model to an <see cref="RSAParameters"/> instance.
        /// </summary>
        /// <param name="rsaSerializationModel">The serialization model.</param>
        /// <returns>The cryptographic RSA parameters.</returns>
        /// <exception cref="NotSupportedException">Thrown, if the data
        ///     in the <paramref name="rsaSerializationModel"/> is not compatible for
        ///     use as cyptographic RSA parameters.</exception>
        public static RSAParameters Convert(RsaSerializationModel rsaSerializationModel)
        {
            if (rsaSerializationModel == null) throw new ArgumentNullException(nameof(rsaSerializationModel));

            try
            {
                return new RSAParameters
                {
                    D = rsaSerializationModel.D == null ? null : System.Convert.FromBase64String(rsaSerializationModel.D),
                    DP = rsaSerializationModel.DP == null ? null : System.Convert.FromBase64String(rsaSerializationModel.DP),
                    DQ = rsaSerializationModel.DQ == null ? null : System.Convert.FromBase64String(rsaSerializationModel.DQ),
                    Exponent = rsaSerializationModel.Exponent == null ? null : System.Convert.FromBase64String(rsaSerializationModel.Exponent),
                    InverseQ = rsaSerializationModel.InverseQ == null ? null : System.Convert.FromBase64String(rsaSerializationModel.InverseQ),
                    Modulus = rsaSerializationModel.Modulus == null ? null : System.Convert.FromBase64String(rsaSerializationModel.Modulus),
                    P = rsaSerializationModel.P == null ? null : System.Convert.FromBase64String(rsaSerializationModel.P),
                    Q = rsaSerializationModel.Q == null ? null : System.Convert.FromBase64String(rsaSerializationModel.Q),
                };
            }
            catch (Exception ex)
            {
                throw new NotSupportedException("Invalid RSA parameters.", ex);
            }
        }

        /// <summary>
        /// Converts cryptograhic RSA parameters to a serialization model instance.
        /// </summary>
        /// <param name="rsaParameters">The cryptographics RSA parameters.</param>
        /// <returns>The serialization model.</returns>
        public static RsaSerializationModel Convert(RSAParameters rsaParameters)
            => new RsaSerializationModel
            {
                D = rsaParameters.D == null ? null : System.Convert.ToBase64String(rsaParameters.D),
                DP = rsaParameters.DP == null ? null : System.Convert.ToBase64String(rsaParameters.DP),
                DQ = rsaParameters.DQ == null ? null : System.Convert.ToBase64String(rsaParameters.DQ),
                Exponent = rsaParameters.Exponent == null ? null : System.Convert.ToBase64String(rsaParameters.Exponent),
                InverseQ = rsaParameters.InverseQ == null ? null : System.Convert.ToBase64String(rsaParameters.InverseQ),
                Modulus = rsaParameters.Modulus == null ? null : System.Convert.ToBase64String(rsaParameters.Modulus),
                P = rsaParameters.P == null ? null : System.Convert.ToBase64String(rsaParameters.P),
                Q = rsaParameters.Q == null ? null : System.Convert.ToBase64String(rsaParameters.Q),
            };
    }
}
