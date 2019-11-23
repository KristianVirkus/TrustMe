using System.Security.Cryptography;

namespace TrustMe.UnitTests
{
    class ScenarioRsa
    {
        public static readonly byte[] DefaultData;
        public static readonly IHash DefaultDataHash;
        public static readonly RsaKey DefaultKey;
        public static readonly RsaCertificate DefaultCertificate;
        public static readonly RsaSignature DefaultCertificateSignature;
        public static readonly RSACryptoServiceProvider DefaultRsa;
        public static readonly RSAParameters DefaultRsaParameters;
        public static readonly RsaKey DefaultSignerKey;
        public static readonly RsaCertificate DefaultSignerCertificate;
        public static readonly byte[] DefaultSignatureData;
        public static readonly RsaSignature DefaultSignature;
        public static readonly byte[] DefaultEmbeddedData;
        public static readonly ChainOfTrust DefaultChain;

        public RSAParameters RsaParameters { get; set; }
        public RsaKey Key { get; set; }

        static ScenarioRsa()
        {
            DefaultData = new byte[] { 0x00, 0x01, 0x02, 0x03 };
            DefaultDataHash = Sha512Hash.Compute(DefaultData);
            DefaultEmbeddedData = new byte[] { 0xff, 0xee, 0xdd, 0xcc };
            DefaultKey = RsaKey.Generate();
            DefaultRsa = DefaultKey.CreateRsa();
            DefaultRsaParameters = DefaultRsa.ExportParameters(true);
            DefaultCertificateSignature = new RsaSignature(Sha512Hash.Compute(new byte[] { 0x12, 0x34, 0xaa, 0xbb }), new byte[] { 0xa1, 0xb2, 0xc3, 0xd4 });
            DefaultCertificate = new RsaCertificate(DefaultRsaParameters, DefaultCertificateSignature);
            DefaultSignerKey = RsaKey.Generate();
            DefaultSignerCertificate = (RsaCertificate)DefaultSignerKey.DeriveCertificate();
            DefaultSignatureData = new byte[] { 0x1f, 0x2f, 0x3f, 0x4f };
            DefaultSignature = new RsaSignature(DefaultSignerCertificate.Hash, DefaultSignatureData);
            DefaultChain = new ChainOfTrust(DefaultSignerCertificate);
        }
    }
}
