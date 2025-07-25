using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using F=System.IO.File;

namespace YukiDNS.CA_CORE
{
    [Route("/CA")]
    public class CAController : Controller
    {
        [HttpPost("InitRootCA")]
        public IActionResult InitRootCA([FromBody] InitRootCARequest req)
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

                return File(F.ReadAllBytes(certPath), "text/x509-certificate");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error generating Root CA certificate: {ex.Message}");
            }
        }

        [HttpGet,
            Route("ca.cer"), Route("ca.crt"), Route("ca.pem"),
            Route("ca.key"), Route("ca.pfx"), Route("ca.p12"), Route("ca.der"), Route("ca.p7b")
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

        [HttpPost("InitSubCA")]
        public IActionResult InitSubCA([FromBody] Layer2Request request)
        {
            string name = string.IsNullOrEmpty(request.Name) ? CA_Service.config.DefaultCAName : request.Name;
            string caname = string.IsNullOrEmpty(request.CAName) ? CA_Service.config.DefaultSelfSignCAName : request.CAName;

            var keyr = new RSACryptoServiceProvider(CA_Service.config.KeySize);
            var key = DotNetUtilities.GetRsaKeyPair(keyr);

            var capem = F.ReadAllText(CA_Service.config.CertDir + "ca.pem");
            var cakeyr = RSACryptoHelper.PemToRSAKey(capem);
            var cakey = DotNetUtilities.GetRsaKeyPair(cakeyr);

            CA_Helper.GenerateLayer2Cert(CA_Service.config, caname, name, cakey, key);
            string subcaPath = Path.Combine(CA_Service.config.CertDir, "subca.crt");
            return File(F.ReadAllBytes(subcaPath), "text/x509-certificate");
        }

        [HttpPost("GenWebServerCert")]
        public IActionResult GenWebServerCert([FromBody] WebServerCertRequest request)
        {
            string name = string.IsNullOrEmpty(request?.Name) ? "defaultServer" : request.Name;
			string dnsNames = request?.DNSNames ?? "";

			var keyr = new RSACryptoServiceProvider(CA_Service.config.KeySize);
            var key = DotNetUtilities.GetRsaKeyPair(keyr);

            string subCaCertPath = Path.Combine(CA_Service.config.CertDir, "subca.crt");
            string subCaKeyPath = Path.Combine(CA_Service.config.CertDir, "subca.pem");

            if (!F.Exists(subCaCertPath) || !F.Exists(subCaKeyPath))
            {
                return StatusCode(404, "Sub CA certificate or key not found. Please initialize Sub CA first.");
            }

            var subCaCert = new X509Certificate2(F.ReadAllBytes(subCaCertPath));
            string caname = subCaCert.Subject;

            var subCaKeyPem = F.ReadAllText(subCaKeyPath);
            var subCaKeyRsa = RSACryptoHelper.PemToRSAKey(subCaKeyPem);
            var subCaKey = DotNetUtilities.GetRsaKeyPair(subCaKeyRsa);

            CA_Helper.GenerateWebServerCert(CA_Service.config, caname, name, dnsNames, subCaKey, key);

            string userCertPath = Path.Combine(CA_Service.config.CertDir, "user.crt");
            return File(F.ReadAllBytes(userCertPath), "text/x509-certificate");
        }

        

    }
}
