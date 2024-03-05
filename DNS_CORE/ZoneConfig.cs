namespace YukiDNS.DNS_CORE
{

    public class ZoneConfig
    {
        public string Name { get; set; }
        public bool DNSSEC { get; set; }
        public string DNSSECKey { get; set; }
        public string DNSSECKeyRecord { get; set; }
        public string DNSSECSalt { get; set; }  
        public string DataFile { get; set; }
    }

}
