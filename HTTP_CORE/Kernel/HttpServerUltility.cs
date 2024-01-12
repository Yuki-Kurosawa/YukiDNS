using System;
using System.Collections.Generic;
using System.IO;
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
            string p= Path.Combine(_basepath , path.Replace("//", "/").Replace("~/", "/").TrimStart('/'));
            Console.WriteLine(_basepath);
            Console.WriteLine(p);
            return p;
        }
    }
}
