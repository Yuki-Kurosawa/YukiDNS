namespace YukiDNS.ACME_CORE
{
    public class ACMEConfig
    {
        public string Directory { get; set; }

        public string Account { get; set; }

        public int ACMEKeyLength { get; set; } = 2048;

        public string[] Names { get; set; }

        public string ChallengeMethod { get; set; } = "HTTP-01";

        public int CertKeyLength { get; set; } = 2048;
    }
}