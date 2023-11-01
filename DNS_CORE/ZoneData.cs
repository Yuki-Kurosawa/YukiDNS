using YukiDNS.DNS_RFC;

namespace YukiDNS.DNS_CORE
{
    public class ZoneData
    {

        public string Name { get; set; }
        public uint TTL { get; set; }
        public QTYPES Type { get; set; }
        public object[] Data { get; set; }
    }
}