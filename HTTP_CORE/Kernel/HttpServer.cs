using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using ha=YukiDNS.HTTP_CORE.HttpApplication;

namespace YukiDNS.HTTP_CORE.Kernel
{
    public class HttpServer
    {
        private HttpListener listen;
        private ha application;

        public HttpServer(string[] prefixes,Config config)
        {
            listen=new HttpListener();
            foreach (string prefix in prefixes)
            {
                listen.Prefixes.Add(prefix);
            }

            application=new ha(config);
            
        }
        public void StopServer()
        {
            listen.Stop();
        }

        public void StartServer()
        {
            listen.Start();
            listen.BeginGetContext(DoWebRequest, listen);
        }

        private void DoWebRequest(IAsyncResult ar)
        {
            try
            {
                HttpListenerContext context = listen.EndGetContext(ar);
                listen.BeginGetContext(DoWebRequest, listen);
                application.ProcessRequest(context);
            }
            catch
            {

            }
        }
    }
    
}
