using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Newtonsoft.Json;

namespace System.Web
{
    public class CSharpHandlerFactory : IHttpHandlerFactory
    {
        public IHttpHandler GetHandler(HttpContext context, string requestType, string url, string pathTranslated)
        {
            string path = context.Request.Path;
            path = context.Server.MapPath("~/" + path);

            /* check if dir */
            bool isDir = Directory.Exists(path);
            /* check if file */
            bool isFile = File.Exists(path);
            if (!isDir && !isFile)
            {
                return new Http404Handler();
            }
            if (isDir && !isFile)
            {
                //Dir
                bool hpFound = false;
                string hpurl = "";
                foreach (string hp in context.Config.defaultPage)
                {
                    if (File.Exists(context.Server.MapPath("~/" + hp)))
                    {
                        hpFound = true;
                        hpurl = hp;
                        break;
                    }
                }
                if (!hpFound)
                {
                    return new Http403Handler();
                }
            }

            //File
            return new CSharpHandler();
        }

        public void ReleaseHandler(IHttpHandler handler)
        {
            
        }
    }
}
