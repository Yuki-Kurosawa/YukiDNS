namespace YukiDNS.ACME_CORE
{
    public class ACMEOrderObject
    {
        public string OrderID { get; set; }
        public string[] Authorizations { get; set; }
        public string FinalizeAction { get; set; }
    }
}