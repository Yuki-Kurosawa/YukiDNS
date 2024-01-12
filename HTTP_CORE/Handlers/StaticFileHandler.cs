using System.IO;
using System.Web;
using Microsoft.Win32;
using YukiDNS.HTTP_CORE.Kernel;

namespace System.Web
{
    public class StaticFileHandler : IHttpHandler
    {
        public bool IsReusable => false;
        

        public void ProcessRequest(HttpContext context)
        {
            string path = context.Server.MapPath("~/" + context.Request.Path);
            Config config = context.Config;
            byte[] fb=File.ReadAllBytes(path);
            FileInfo f = new FileInfo(path);

            try
            {
                context.Response.ContentType = Registry.GetValue($@"HKEY_CLASSES_ROOT\{f.Extension}", "Content Type", "text/plain").ToString();
            }
            catch
            {
                context.Response.ContentType = "text/plain";
            }
            context.Response.WriteBytes(fb);
        }
    }
}