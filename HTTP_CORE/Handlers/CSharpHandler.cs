using System.CodeDom.Compiler;
using System.IO;
using YukiDNS.HTTP_CORE.Kernel;
using Microsoft.CSharp;
using Newtonsoft.Json;

namespace System.Web
{
    public class CSharpHandler : IHttpHandler
    {
        public bool IsReusable => false;
        

        public void ProcessRequest(HttpContext context)
        {
            string path = context.Server.MapPath("~/" + context.Request.Path);

            //try
            //{

            //    Config config = context.Config;
            //    string code = File.ReadAllText(path);
            //    CSharpCodeProvider ccp = new CSharpCodeProvider();
            //    string dll = context.Server.MapPath("~/bin/x86/Debug/RubyWeb.dll");
            //    string json = context.Server.MapPath("~/bin/x86/Debug/Newtonsoft.Json.dll");
            //    string fssi = context.Server.MapPath("~/bin/x86/Debug/Demo.exe");
            //    string wepay = context.Server.MapPath("~/bin/x86/Debug/wepay.dll");
            //    string alipay = context.Server.MapPath("~/bin/x86/Debug/AopSdk.dll");
            //    CompilerParameters cp =
            //        new CompilerParameters(new[] { dll, "System.dll", "System.Data.dll", "System.Linq.dll", "System.Xml.dll", wepay, json, fssi, alipay })
            //        {
            //            GenerateExecutable = false,
            //            GenerateInMemory = true,
            //            CompilerOptions = $@"/langversion:Default /platform:x86"
            //        };

            //    CompilerResults cr = ccp.CompileAssemblyFromFile(cp, path);
            //    Type[] ts = cr.CompiledAssembly.GetExportedTypes();
            //    Type ty = null;
            //    foreach (var t in ts)
            //    {
            //        Type i = t.GetInterface("System.Web.IHttpHandler");
            //        if (i != null)
            //        {
            //            ty = t;
            //            break;
            //        }
            //    }
            //    if (ty != null)
            //    {
            //        IHttpHandler h = (IHttpHandler)ty.GetConstructor(new Type[0])?.Invoke(null);
            //        h.ProcessRequest(context);
            //    }
            //}
            //catch (Exception ex)
            //{
            //    context.Response.StatusCode = 500;
            //    context.Response.ContentType = "text/html";
            //    context.Response.Write(BuildResponse(context, path, ex.InnerException==null?ex:ex.InnerException));
            //}
        }

        private string BuildResponse(HttpContext context,string path,Exception ex)
        {
            return "";//YukiDNS.HTTP_CORE.Properties.Resources.Http500.Replace("{URL}", context.Request.Path).Replace("{WEBVER}", "1.0.0").Replace("{RVER}", "1.0.0")
                //.Replace("{ExceptionMessage}",ex.Message.Replace("\r\n","<br/>")).Replace("{ExceptionStack}",ex.StackTrace);
        }
    }
}