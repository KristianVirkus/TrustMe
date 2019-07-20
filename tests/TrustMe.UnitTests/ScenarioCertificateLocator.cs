using Moq;

namespace TrustMe.UnitTests
{
	class Scenario3
	{
		public ICertificateLocator CertificateLocator { get; set; }
		public ChainOfTrust ChainWithLocator { get; set; }

		public Scenario3()
		{
			this.CertificateLocator = Mock.Of<ICertificateLocator>();
			this.ChainWithLocator = new ChainOfTrust(this.CertificateLocator, Scenario.DefaultSignerCertificate);
		}
	}
}
