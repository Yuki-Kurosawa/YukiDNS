using System.Reflection;

namespace YukiDNS.HTTP_CORE.Kernel
{
    public class Config
    {
        public int siteId { get; set; }

        public string siteName { get; set; }

        public Prefix[] prefix { get; set; }

        public string GetPrefixString()
        {
            string pre = "";
            foreach (Prefix prefixobj in prefix)
            {
                pre += $@"{prefixobj.host}:{prefixobj.port}({prefixobj.scheme});";
            }
            pre = pre.Trim(';');
            return pre;
        }

        public string path { get; set; }

        public string[] defaultPage { get; set; }
    }

    public class Prefix
    {
        public string scheme { get; set; }

        public string host { get; set; }

        public int port { get; set; }
    }
}