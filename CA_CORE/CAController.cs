using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.Collections.Generic;
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

        [HttpPost("/ocsp")]
        public IActionResult OCSP()
        {
            var capem = F.ReadAllText(CA_Service.config.CertDir + "ca.pem");
            var cacert = F.ReadAllText(CA_Service.config.CertDir + "ca.crt");
            var cakeyr = RSACryptoHelper.PemToRSAKey(capem);
            var cakey = DotNetUtilities.GetRsaKeyPair(cakeyr);

            X509Certificate2 cert = CA_Helper.LoadPEMCert(CA_Service.config.CertDir + "ca.crt", CA_Service.config.CertDir + "ca.pem");


            // 2. 解析 OCSP 请求（这部分需要从 Request.Body 读取）
            // 假设你从 Request.Body 读取了请求字节 `requestBytes`
            byte[] requestBytes;
            using (var ms = new MemoryStream())
            {
                Request.Body.CopyTo(ms); // 同步读取，如果你没有异步，否则用 CopyToAsync
                requestBytes = ms.ToArray();
            }

            OcspReq ocspReq;
            try
            {
                ocspReq = new OcspReq(requestBytes);
            }
            catch (Exception ex)
            {
                // 请求格式错误，返回一个错误响应
                OCSPRespGenerator errGen = new OCSPRespGenerator();
                return File(errGen.Generate((int)OcspRespStatus.MalformedRequest, null).GetEncoded(), "application/ocsp-response");
            }

            // 假设只处理第一个证书查询
            Req singleRequest = ocspReq.GetRequestList()[0];
            CertificateID certId = singleRequest.GetCertID();

            // 3. 查询证书状态（替换为你的实际逻辑）
            CertificateStatus certStatus = Org.BouncyCastle.Ocsp.CertificateStatus.Good; // 假设是Good
            //CertificateStatus certStatus = new RevokedStatus(DateTime.Now, CrlReason.CACompromise); // 假设是Good

            // --- 构造 Basic OCSP 响应 ---
            BasicOcspRespGenerator basicGen = new BasicOcspRespGenerator(
                cakey.Public
            );
            basicGen.AddResponse(certId, certStatus); // 添加证书状态

            var clientExtensions = ocspReq.RequestExtensions; // 应该从 ocspReq 获取，而不是 request
            if (clientExtensions != null)
            {
                Org.BouncyCastle.Asn1.X509.X509Extension nonceExtension = clientExtensions.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
                if (nonceExtension != null)
                {
                    basicGen.SetResponseExtensions(new X509Extensions(new Dictionary<DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension>() { { OcspObjectIdentifiers.PkixOcspNonce, nonceExtension } }));
                }
            }


            // 签名 Basic OCSP 响应
            Org.BouncyCastle.X509.X509Certificate[] chain = { DotNetUtilities.FromX509Certificate(cert) }; // 响应者证书链
            BasicOcspResp basicResp = basicGen.Generate("SHA256withRSA", cakey.Private, chain, DateTime.UtcNow);


            // --- 封装到 ResponseBytes 并生成最终 OcspResp ---
            OCSPRespGenerator rg = new OCSPRespGenerator(); // 重新创建或复用
            var rr = rg.Generate(
                (int)OcspResponseStatus.Successful,
                basicResp // 提供实际数据
            );

            return File(rr.GetEncoded(), "application/ocsp-response");
        }

    }
}
