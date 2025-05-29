using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using F=System.IO.File;

namespace YukiDNS.CA_CORE
{
    [Route("/CA")]
    public class CAController : Controller
    {
        [HttpPost("InitRootCA")]
        public IActionResult InitRootCA([FromBody]InitRootCARequest req)
        {
            string certPath = Path.Combine("certs", "ca.crt");

            if (F.Exists(certPath))
            {
                return StatusCode(403, "Root CA Initialzed, DO NOT try to initialize again");
            }

            if (req == null || string.IsNullOrEmpty(req.Name))
            {
                return BadRequest("Invalid request data.");
            }
            try
            {
                var keyr = new RSACryptoServiceProvider(CA_Service.config.KeySize);
                var key = DotNetUtilities.GetRsaKeyPair(keyr);    
                
                CA_Helper.GenerateSelfSignCert(CA_Service.config, req.Name, key);

                return File(F.ReadAllBytes(certPath),"text/x509-certificate");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error generating Root CA certificate: {ex.Message}");
            }
        }

        [HttpGet,
            Route("ca.cer"),Route("ca.crt"),Route("ca.pem"),
            Route("ca.key"),Route("ca.pfx"),Route("ca.p12"),Route("ca.der"),Route("ca.p7b")
            ]
        public IActionResult GetRootCACerts()
        {
            string certPath = Path.Combine("certs", "ca.crt");

            if (!F.Exists(certPath))
            {
                return StatusCode(404, "Root CA Not Initialzed, please initialize first");
            }

            return File(F.ReadAllBytes(certPath), "text/x509-certificate");
        }
        
    }
}
