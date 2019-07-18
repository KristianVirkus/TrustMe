namespace TrustMe
{
	public interface IChainOfTrust
	{
		ICertificate RequiredCertificateInChain { get; }
		void Verify(ICertificate certificate);
	}
}
