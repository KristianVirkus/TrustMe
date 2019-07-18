using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace TrustMe.UnitTests
{
	class Scenario
	{
		public static readonly byte[] DefaultData;
		public static readonly IHash DefaultDataHash;
		public static readonly RsaKey DefaultKey;
		public static readonly RsaCertificate DefaultCertificate;
		public static readonly RsaSignature DefaultCertificateSignature;
		public static readonly RSACryptoServiceProvider DefaultRsa;
		public static readonly RSAParameters DefaultRsaParameters;
		public static readonly byte[] DefaultSignerCertificateHashData;
		public static readonly IHash DefaultSignerCertificateHash;
		public static readonly byte[] DefaultSignatureData;
		public static readonly RsaSignature DefaultSignature;
		public static readonly byte[] DefaultEmbeddedData;
		public static readonly IHash DefaultEmbeddedDataHash;

		public RSAParameters RsaParameters { get; set; }
		public RsaKey Key { get; set; }

		static Scenario()
		{
			DefaultData = new byte[] { 0x00, 0x01, 0x02, 0x03 };
			DefaultDataHash = Sha512Hash.Compute(DefaultData);
			DefaultEmbeddedData = new byte[] { 0xff, 0xee, 0xdd, 0xcc };
			DefaultEmbeddedDataHash = Sha512Hash.Compute(DefaultEmbeddedData);
			DefaultKey = RsaKey.Generate();
			DefaultRsa = DefaultKey.CreateRsa();
			DefaultRsaParameters = DefaultRsa.ExportParameters(true);
			DefaultCertificateSignature = new RsaSignature(Sha512Hash.Compute(new byte[] { 0x12, 0x34, 0xaa, 0xbb }), new byte[] { 0xa1, 0xb2, 0xc3, 0xd4 });
			DefaultCertificate = new RsaCertificate(DefaultRsaParameters, DefaultCertificateSignature);
			DefaultSignerCertificateHashData = new byte[] { 0x10, 0x20, 0x30, 0x40 };
			DefaultSignerCertificateHash = Sha512Hash.Compute(DefaultSignerCertificateHashData);
			DefaultSignatureData = new byte[] { 0x1f, 0x2f, 0x3f, 0x4f };
			DefaultSignature = new RsaSignature(DefaultSignerCertificateHash, DefaultSignatureData);
		}
	}
}
