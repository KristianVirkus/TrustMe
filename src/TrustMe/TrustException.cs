[System.Serializable]
public class TrustException : System.Exception
{
	public TrustException() { }
	public TrustException(string message) : base(message) { }
	public TrustException(string message, System.Exception inner) : base(message, inner) { }
	protected TrustException(
	  System.Runtime.Serialization.SerializationInfo info,
	  System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
}