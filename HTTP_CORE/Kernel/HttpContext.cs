using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using YukiDNS.HTTP_CORE.Kernel;

namespace System.Web
{
    public class HttpContext
    {
        private HttpListenerContext _context;
        private HttpServerUltility _server;
        private Config _config;

        public HttpContext(HttpListenerContext context,Config config)
        {
            _context = context;
            _server=new HttpServerUltility(config.path);
            _config = config;
        }

        public HttpRequest Request =>new HttpRequest(_context.Request);
        

        public HttpResponse Response => new HttpResponse(_context.Response);

        public HttpServerUltility Server => _server;

        public Config Config => _config;
    }
}
