using System.ComponentModel;

namespace YukiDNS.WHOIS_CORE
{
    public class RegistryInfoObject
    {

        [Description("Registry {0} ID")]
        public string ID { get; set; }

        [Description("{0} Name")]
        public string Name { get; set; }

        [Description("{0} Organization")]
        public string Organization { get; set; }

        [Description("{0} Street")]
        public string Street { get; set; }

        [Description("{0} City")]
        public string City { get; set; }

        [Description("{0} State/Province")]
        public string StateProvince { get; set; }

        [Description("{0} Postal Code")]
        public string PostalCode { get; set; }

        [Description("{0} Country")]
        public string Country { get; set; }

        [Description("{0} Phone")]
        public string Phone { get; set; }

        [Description("{0} Fax")]
        public string Fax { get; set; }

        [Description("{0} Email")]
        public string Email { get; set; }
    }
}