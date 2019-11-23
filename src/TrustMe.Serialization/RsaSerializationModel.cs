namespace TrustMe.Serialization
{
    /// <summary>
    /// Represents the cryptographic RSA parameters model.
    /// </summary>
    public class RsaSerializationModel
    {
        public string D { get; set; }
        public string DP { get; set; }
        public string DQ { get; set; }
        public string Exponent { get; set; }
        public string InverseQ { get; set; }
        public string Modulus { get; set; }
        public string P { get; set; }
        public string Q { get; set; }
    }
}
