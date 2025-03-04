using System.ComponentModel;

namespace YukiDNS.WHOIS_CORE
{
    public class WHOISDBObject
    {
        #region Basic Info

        [Description("Domain Name")]
        public string DomainName { get; set; }

        [Description("Registry Domain ID")]
        public string RegistryDomainID { get; set; }

        [Description("Registrar WHOIS Server")]
        public string RegistrarWHOISServer { get; set; }

        [Description("Registrar URL")]
        public string RegistrarURL { get; set; }

        [Description("Updated Date")]
        public string UpdatedDate { get; set; }

        [Description("Creation Date")]
        public string CreationDate { get; set; }

        [Description("Registry Expiry Date")]
        public string RegistryExpiryDate { get; set; }

        [Description("Registrar")]
        public string Registrar { get; set; }

        [Description("Registrar IANA ID")]
        public int RegistrarIANAID { get; set; }

        [Description("Registrar Abuse Contact Email")]
        public string RegistrarAbuseContactEmail { get; set; }

        [Description("Registrar Abuse Contact Phone")]
        public string RegistrarAbuseContactPhone { get; set; }

        [Description("Domain Status")]
        public DomainEPPStatus[] DomainStatus { get; set; }

        #endregion

        #region Contact Info

        [Description("Registrant")]
        public RegistryInfoObject Registrant { get; set; }

        [Description("Admin")]
        public RegistryInfoObject Admin { get; set; }

        [Description("Tech")]
        public RegistryInfoObject Tech { get; set; }

        [Description("Billing")]
        public RegistryInfoObject Billing { get; set; }

        #endregion

        #region Name Server Info
        [Description("Name Server")]
        public string[] NameServer { get; set; }
        #endregion

    }
}