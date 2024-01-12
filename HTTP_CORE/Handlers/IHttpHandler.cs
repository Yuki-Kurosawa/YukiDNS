using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace System.Web
{
    public interface IHttpHandler
    {
        bool IsReusable { get; }
        void ProcessRequest(HttpContext context);
    }
}
