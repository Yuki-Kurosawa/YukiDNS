using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace System.Web
{
    public class Http404Handler : IHttpHandler
    {
        public bool IsReusable => false;

        public void ProcessRequest(HttpContext context)
        {
            context.Response.StatusCode = 404;
            context.Response.Write(BuildResponse(context));
        }

        private string BuildResponse(HttpContext context)
        {
            return "";// YukiDNS.HTTP_CORE.Properties.Resources.Http404.Replace("{URL}",context.Request.Path).Replace("{WEBVER}","1.0.0").Replace("{RVER}","1.0.0");
        }
    }
}
