using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Ocsp;
using System;
using System.IO;

namespace YukiDNS.DNS_CORE
{
    public class DNSQueryController:Controller
    {
        [HttpPost(),Route("/dns-query")]
        public IActionResult PostDNSQuery()
        {
            var sr = new BinaryReader(HttpContext.Request.Body);
            byte[] req = new byte[(int)HttpContext.Request.ContentLength];
            sr.Read(req,0, req.Length);

            var dns = DNSService.ParseDNSRequest(req);

            var dret = DNSService.Resolve(dns);

            byte[] buf = dret.To();

            return File(buf,"application/dns-message");
        }

        [HttpGet(), Route("/dns-query")]
        public IActionResult GetDNSQuery([FromQuery]string dns)
        {
            byte[] req = Convert.FromBase64String(dns);

            var qdns = DNSService.ParseDNSRequest(req);

            var dret = DNSService.Resolve(qdns);

            byte[] buf = dret.To();

            return File(buf, "application/dns-message");
        }
    }
}
