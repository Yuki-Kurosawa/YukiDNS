using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using F=System.IO.File;

namespace YukiDNS.ACME_CORE
{
    [Route("/.well-known")]
    [ApiController]
    public class WellKnownController : ControllerBase
    {
        [Route("acme-challenge/{challenge}")]
        [HttpGet]
        public string ACMEChallenge(string challenge)
        {
            if(!Directory.Exists(".well-known/acme-challenge"))
            {
                Directory.CreateDirectory(".well-known/acme-challenge");
            }

            try
            {
                return F.ReadAllText(".well-known/acme-challenge/" + challenge);
            }
            catch
            {
                HttpContext.Response.StatusCode = 404;
                return "";
            }
        }
    }
}
