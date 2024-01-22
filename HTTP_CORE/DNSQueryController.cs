using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;

namespace YukiDNS.HTTP_CORE
{
    public class DNSQueryController:Controller
    {
        [HttpPost(),Route("/dns-query")]
        public IActionResult PostDNSQuery()
        {
            var sr = new BinaryReader(HttpContext.Request.Body);
            byte[] dns = new byte[(int)HttpContext.Request.ContentLength];
            sr.Read(dns,0, dns.Length);
            return File(dns,"application/dns-message");
        }

        [HttpGet(), Route("/dns-query")]
        public IActionResult GetDNSQuery([FromQuery]string dns)
        {
            byte[] dnsb = Convert.FromBase64String(dns);
            return File(dnsb, "application/dns-message");
        }
    }
}
