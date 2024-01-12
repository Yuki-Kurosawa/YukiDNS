using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using YukiDNS.HTTP_CORE.Kernel;

namespace YukiDNS.HTTP_CORE
{
    public class HttpApplication
    {
        private Config _config;

        public HttpApplication(Config config)
        {
            _config = config;
        }

        public void ProcessRequest(HttpListenerContext context)
        {
            /* ProcessRequest */
            var con = new HttpContext(context, _config);
            con.Response.ContentEncoding = Encoding.UTF8;
            context.Response.SendChunked = false;
            con.Response.ContentLength = 0;
            IHttpHandler handler = null;
            switch (new FileInfo(con.Server.MapPath("~" + con.Request.Path)).Extension) //.txt
            {
                case ".cs":
                    handler = new CSharpHandlerFactory().GetHandler(con, con.Request.Method,
                        con.Request.Url.AbsoluteUri,
                        con.Request.Path);
                    break;
                default:
                    handler = new StaticFileHandlerFactory().GetHandler(con, con.Request.Method,
                        con.Request.Url.AbsoluteUri,
                        con.Request.Path);
                    break;
            }
            if (handler != null)
            {
                handler.ProcessRequest(con);
            }
            con.Response.End();
        }
    }
}
