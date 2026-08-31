using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace YukiDNS.WHOIS_CORE
{
    /// <summary>
    /// RDAP Domain Response, per RFC 7483.
    /// </summary>
    public class RDAPResponseProfile
    {
        public string[] rdapConformance { get; set; }

        public string objectClassName { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string handle { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string ldhName { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string[] status { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string port43 { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<RDAPEvent> events { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<RDAPEntity> entities { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<RDAPNameServer> nameservers { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<RDAPLink> links { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<RDAPNotice> notices { get; set; }
    }

    /// <summary>
    /// RDAP event object (RFC 7483 §5.6).
    /// </summary>
    public class RDAPEvent
    {
        public string eventAction { get; set; }

        public string eventDate { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string eventActor { get; set; }
    }

    /// <summary>
    /// RDAP link object (RFC 7483 §5.2).
    /// </summary>
    public class RDAPLink
    {
        public string value { get; set; }

        public string rel { get; set; }

        public string href { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string type { get; set; }
    }

    /// <summary>
    /// RDAP nameserver object (RFC 7483 §5.4).
    /// </summary>
    public class RDAPNameServer
    {
        public string objectClassName { get; set; }

        public string ldhName { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<RDAPLink> links { get; set; }
    }

    /// <summary>
    /// RDAP entity object (RFC 7483 §5.7), carrying a jCard vcardArray.
    /// </summary>
    public class RDAPEntity
    {
        public string objectClassName { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string handle { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string[] roles { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public object[] vcardArray { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<RDAPLink> links { get; set; }
    }

    /// <summary>
    /// RDAP notice object (RFC 7483 §5.1).
    /// </summary>
    public class RDAPNotice
    {
        public string[] title { get; set; }

        public string[] description { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<RDAPLink> links { get; set; }
    }

    /// <summary>
    /// RDAP error response (RFC 7483 §9).
    /// </summary>
    public class RDAPError
    {
        public string[] rdapConformance { get; set; }

        public int errorCode { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string title { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string[] description { get; set; }
    }
}
