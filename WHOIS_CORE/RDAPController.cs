using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace YukiDNS.WHOIS_CORE
{
    [Route("[controller]")]
    [ApiController]
    //[EnableCors("DefaultCorsPolicy")]
    public class RDAPController : ControllerBase
    {
        [HttpGet,Produces("application/rdap+json"),Route("test")]
        public object Test()
        {
            return new { };
        }
    }
}
