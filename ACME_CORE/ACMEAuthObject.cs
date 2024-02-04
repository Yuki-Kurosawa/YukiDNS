using Org.BouncyCastle.Asn1.X509;

namespace YukiDNS.ACME_CORE
{
    public class ACMEAuthObject
    {
        public ACMEAuthIdentifer identifier { get; set; }

        public ACMEAuthChallenges[] challenges { get; set; }

        public string status { get; set; }

        public string expires { get; set; }

    }


    public class ACMEAuthError
    {
        public string type { get; set; }
        public string detail { get; set; }
        public int status { get; set; }
    }


    public class ACMEAuthChallenges
    {
        public string type { get; set; }
        public string status { get; set; }
        public string url { get; set; }
        public string token { get; set; }

        public ACMEAuthError error { get; set; }

    }



    public class ACMEAuthIdentifer
    {
        public string type { get; set; }

        public string value { get; set; }
    }
}
