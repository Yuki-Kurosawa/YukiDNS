using System;

namespace YukiDNS.WHOIS_CORE
{
    public class RdapStatusAttribute : Attribute
    {
        public RdapStatusAttribute(string desc)
        {
            Description = desc;
        }

        public string Description { get; }
    }
}