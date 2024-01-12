using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace YukiDNS.HTTP_CORE.Kernel
{
    public class HttpServerUltility
    {
        private string _basepath;

        public HttpServerUltility(string basepath)
        {
            _basepath = basepath;
        }

        public string MapPath(string path)
        {
            return _basepath + path.Replace("//","/").Replace("~/", "/").Replace('/','\\');
        }
    }
}
