using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace TrustMe
{
	/// <summary>
	/// Implements helper functionality.
	/// </summary>
	public static class Helpers
	{
		/// <summary>
		/// Computes the hash of certain parameters used in RSA certificates and keys.
		/// </summary>
		/// <param name="rsaParameters">The cryptographic RSA parameters.</param>
		/// <param name="includePrivateParameters">true to include cryptographic RSA private parameters,
		///		false to include only public ones.</param>
		/// <param name="embeddedData">The embedded data to consider for computing
		///		the hash.</param>
		/// <returns>The hash.</returns>
		public static IHash ComputeRsaHash(RSAParameters rsaParameters, bool includePrivateParameters,
			IEnumerable<byte> embeddedData)
		{
			using (var stream = new MemoryStream())
			{
				var data = new List<byte[]>();
				data.Add(rsaParameters.Exponent);
				data.Add(rsaParameters.Modulus);
				if (includePrivateParameters)
				{
					data.Add(new byte[] { 0x01 });
					data.Add(rsaParameters.D);
					data.Add(rsaParameters.DP);
					data.Add(rsaParameters.DQ);
					data.Add(rsaParameters.InverseQ);
					data.Add(rsaParameters.P);
					data.Add(rsaParameters.Q);
				}
				else
				{
					data.Add(new byte[] { 0x00 });
				}

				if (embeddedData != null)
				{
					data.Add(new byte[] { 0x01 });
					data.Add(Sha512Hash.Compute(embeddedData.ToArray()).Hash.ToArray());
				}
				else
				{
					data.Add(new byte[] { 0x00 });
				}

				int i = 0;
				foreach (var d in data)
				{
					var iBytes = BitConverter.GetBytes(i);
					if (!BitConverter.IsLittleEndian) iBytes = iBytes.Reverse().ToArray();
					stream.Write(iBytes, 0, iBytes.Length);
					var info = d;
					if (!BitConverter.IsLittleEndian) info = info.Reverse().ToArray();
					stream.Write(info, 0, info.Length);
				}

				stream.Position = 0;
				return Sha512Hash.Compute(stream);
			}
		}

		/// <summary>
		/// Computes the hash of certain parameters used in RSA certificates and keys.
		/// </summary>
		/// <param name="rsaParameters">The cryptographic RSA parameters.</param>
		/// <param name="includePrivateParameters">true to include cryptographic RSA private parameters,
		///		false to include only public ones.</param>
		/// <param name="embeddedData">The embedded data to consider for computing
		///		the hash.</param>
		///	<param name="signature">The cryptographic RSA signature.</param>
		/// <returns>The hash.</returns>
		public static IHash ComputeRsaHashWithSignature(RSAParameters rsaParameters, bool includePrivateParameters,
			IEnumerable<byte> embeddedData, RsaSignature signature)
		{
			using (var stream = new MemoryStream())
			{
				var data = new List<byte[]>();
				data.Add(rsaParameters.Exponent);
				data.Add(rsaParameters.Modulus);
				if (includePrivateParameters)
				{
					data.Add(new byte[] { 0x01 });
					data.Add(rsaParameters.D);
					data.Add(rsaParameters.DP);
					data.Add(rsaParameters.DQ);
					data.Add(rsaParameters.InverseQ);
					data.Add(rsaParameters.P);
					data.Add(rsaParameters.Q);
				}
				else
				{
					data.Add(new byte[] { 0x00 });
				}

				if (embeddedData != null)
				{
					data.Add(new byte[] { 0x01 });
					data.Add(Sha512Hash.Compute(embeddedData.ToArray()).Hash.ToArray());
				}
				else
				{
					data.Add(new byte[] { 0x00 });
				}

				if (signature != null)
				{
					data.Add(new byte[] { 0x01 });
					data.Add(signature.Hash.Hash.ToArray());
				}
				else
				{
					data.Add(new byte[] { 0x00 });
				}

				int i = 0;
				foreach (var d in data)
				{
					var iBytes = BitConverter.GetBytes(i);
					if (!BitConverter.IsLittleEndian) iBytes = iBytes.Reverse().ToArray();
					stream.Write(iBytes, 0, iBytes.Length);
					var info = d;
					if (!BitConverter.IsLittleEndian) info = info.Reverse().ToArray();
					stream.Write(info, 0, info.Length);
				}

				stream.Position = 0;
				return Sha512Hash.Compute(stream);
			}
		}
	}
}
