using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace YukiDNS.HTTP_CORE.Kernel
{
    public static class ConfigParser
    {
        public static Config[] ParseMachineConfig(string siteConf)
        {
            if (!File.Exists(siteConf)) throw new ConfigParseException("站点设置存储丢失或损坏",siteConf, -1);
            string conf = File.ReadAllText(siteConf);
            try
            {
                return JsonConvert.DeserializeObject<Config[]>(conf);
            }
            catch (Exception ex)
            {
                throw new ConfigParseException("站点设置存储丢失或损坏", siteConf,-1);
            }
        }
    }
}
