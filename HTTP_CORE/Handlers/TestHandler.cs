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
    public class TestHandler
    {
        public bool IsReusable => false;

        public void ProcessRequest(HttpContext context)
        {
            context.Response.Write("Test OK for Test Handler");
            HttpRequest req = context.Request;
            List<dynamic> qs = new List<dynamic>(), f = new List<dynamic>(), hs = new List<dynamic>();
            string body = req.Body;
            foreach (var key in req.QueryString.AllKeys)
            {
                qs.Add(new { key, value = req.QueryString[key] });
            }
            foreach (var key in req.Form.AllKeys)
            {
                f.Add(new { key, value = req.Form[key] });
            }
            foreach (var key in req.Headers.AllKeys)
            {
                hs.Add(new { key, value = req.Headers[key] });
            }
            context.Response.ContentType = "text/json";
            context.Response.Write(JsonConvert.SerializeObject(new
            {
                QueryString = qs,
                Form = f,
                Header = hs,
                Body = body,
                req.Path
            }));
        }
    }
}
