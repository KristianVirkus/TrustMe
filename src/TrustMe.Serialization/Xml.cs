using System;
using System.IO;
using System.Xml.Serialization;

namespace TrustMe.Serialization
{
    /// <summary>
    /// Implements XML serialization for keys and certificates.
    /// </summary>
    public static class Xml
    {
        /// <summary>
        /// Serializes a <paramref name="key"/> to a <paramref name="stream"/>.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="stream">The destination stream.</param>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="key"/> or <paramref name="stream"/>
        ///     is null.</exception>
        /// <exception cref="Exception">Thrown, if any error
        ///     occurred serializing or writing the data.</exception>
        public static void Serialize(RsaKey key, Stream stream)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var model = SerializationModelConverter.Convert(key: key);

            var serializer = new XmlSerializer(typeof(SerializationModel));
            serializer.Serialize(stream, model);
            stream.Flush();
        }

        /// <summary>
        /// Serializes a <paramref name="certificate"/> to a <paramref name="stream"/>.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="stream">The destination stream.</param>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="certificate"/> or <paramref name="stream"/>
        ///     is null.</exception>
        /// <exception cref="Exception">Thrown, if any error
        ///     occurred serializing or writing the data.</exception>
        public static void Serialize(RsaCertificate certificate, Stream stream)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var model = SerializationModelConverter.Convert(certificate: certificate);

            var serializer = new XmlSerializer(typeof(SerializationModel));
            serializer.Serialize(stream, model);
            stream.Flush();
        }

        /// <summary>
        /// Deserializes a key from a <paramref name="stream"/>.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>The key.</returns>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="stream"/> is null.</exception>
        /// <exception cref="Exception">Thrown, if any error
        ///     occurred deserializing or reading the data.</exception>
        public static IKey DeserializeKey(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            try
            {
                var serializer = new XmlSerializer(typeof(SerializationModel));
                var model = (SerializationModel)serializer.Deserialize(stream);
                return SerializationModelConverter.ConvertKeyModel(model: model);
            }
            catch (Exception ex)
            {
                throw new NotSupportedException("The key data is invalid or not supported.", ex);
            }
        }

        /// <summary>
        /// Deserializes a certificate from a <paramref name="stream"/>.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>The key.</returns>
        /// <exception cref="ArgumentNullException">Thrown, if
        ///     <paramref name="stream"/> is null.</exception>
        /// <exception cref="Exception">Thrown, if any error
        ///     occurred deserializing or reading the data.</exception>
        public static ICertificate DeserializeCertificate(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            try
            {
                var serializer = new XmlSerializer(typeof(SerializationModel));
                var model = (SerializationModel)serializer.Deserialize(stream);
                return SerializationModelConverter.ConvertCertificateModel(model: model);
            }
            catch (Exception ex)
            {
                throw new NotSupportedException("The certificate data is invalid or not supported.", ex);
            }
        }
    }
}
