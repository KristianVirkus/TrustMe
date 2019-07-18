namespace TrustMe
{
	public interface ICertificateLocator
	{
		ICertificate Get(IHash hash);
	}

	public interface ICertificateLocator<TCertificate> : ICertificateLocator
	{
		new TCertificate Get(IHash hash);
	}
}
