using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
//using YukiDNS.HTTP_CORE.Properties;

namespace System.Web
{
    public class Http403Handler : IHttpHandler
    {
        public bool IsReusable => false;

        public void ProcessRequest(HttpContext context)
        {
            context.Response.StatusCode = 403;
            context.Response.Write(BuildResponse(context));
        }

        private string BuildResponse(HttpContext context)
        {
            return "";// YukiDNS.HTTP_CORE.Properties.Resources.Http403.Replace("{URL}",context.Request.Path).Replace("{WEBVER}","1.0.0").Replace("{RVER}","1.0.0");
        }
    }
}
