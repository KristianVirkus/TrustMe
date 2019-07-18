using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using TrustMe;

namespace SignAndVerifyInputSample
{
	class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("Hello!");
			Console.WriteLine("Let me show you the basics of cryptography with the TrustMe library for Dotnet Core.");
			Console.WriteLine();

			var key = RsaKey.Generate();
			Console.WriteLine($"Generated sample private key (abbr.): {toHex(key.Hash.Hash).Substring(0, 8)}");
			Console.WriteLine("This is used to sign data and thus prove its integrity. Usually this is pre-generated and stored in a file kept secret\nand never to be included in publicly available applications.");
			Console.WriteLine();

			var certificate = key.DeriveCertificate();
			Console.WriteLine($"This public key (or certificate) is derived from it (abbr.): {toHex(certificate.Hash.Hash).Substring(0, 8)}");
			Console.WriteLine("It may be included as a \"hidden\" constant (by means of hard to find and replace in decompiled or disassembled code) in\nany application willing to test the integrity of data expected to come from a known and trusted party.");
			Console.WriteLine();

			Console.Write("Enter some text: ");
			var input = Console.ReadLine();
			var inputHash = Sha512Hash.Compute(Encoding.UTF8.GetBytes(input));
			Console.WriteLine($"The hash value of the input is (abbr.): {toHex(inputHash.Hash).Substring(0, 8)}");
			Console.WriteLine("The hash value is always exactly the same for the same input.");
			Console.WriteLine();

			var signature = key.Sign(inputHash);
			Console.WriteLine($"Signed with the private key, the signature of the input is (abbr.): {toHex(signature.Signature).Substring(0, 8)}");
			Console.WriteLine();

			Console.Write("Checking the signature against the public key (or certificate), should be valid: ");
			try
			{
				certificate.Verify(inputHash, signature);
				Console.WriteLine("valid");
			}
			catch (TrustException ex)
			{
				Console.WriteLine($"invalid,\n{ex.Message}");
			}
			Console.WriteLine();

			Console.Write("Checking the signature against some different arbitrary public key (or certificate), should be invalid: ");
			try
			{
				RsaKey.Generate().DeriveCertificate().Verify(inputHash, signature);
				Console.WriteLine("valid");
			}
			catch (TrustException ex)
			{
				Console.WriteLine($"invalid,\n{ex.Message}");
			}
		}

		static string toHex(IEnumerable<byte> data)
			=> string.Join("", data.Select(b => b.ToString("X")));
	}
}
