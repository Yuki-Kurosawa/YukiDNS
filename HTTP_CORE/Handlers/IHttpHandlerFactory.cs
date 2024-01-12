using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace System.Web
{
    public interface IHttpHandlerFactory
    {
        IHttpHandler GetHandler(HttpContext context, string requestType, string url, string pathTranslated);
        void ReleaseHandler(IHttpHandler handler);
    }
}
