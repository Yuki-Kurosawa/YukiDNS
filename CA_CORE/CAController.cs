using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using F = System.IO.File;

namespace YukiDNS.CA_CORE
{
    /// <summary>
    /// CA HTTP 接口。签发一律入库、按序列号落盘；私钥绝不通过 HTTP 返回。
    /// - 支持 RSA / EC（由策略或 CSR 密钥类型决定），链内必须同类型。
    /// - CSR 模式（POST /CA/SignCSR）：私钥由请求方自持，CA 只签公钥。
    /// - AIA / OCSP / CRL 由 CA_Service 按「直接签发者」生成。
    /// </summary>
    [Route("/CA")]
    public class CAController : Controller
    {
        private IActionResult IssueOk(CertIssueResult r)
        {
            return Ok(new
            {
                serial = r.Record.Serial,
                kind = r.Record.Kind,
                subject = r.Record.Subject,
                issuerSerial = r.Record.IssuerSerial,
                keyType = r.Record.KeyType,
                keyParams = r.Record.KeyParams,
                cert = r.CertPEM
            });
        }

        /// <summary>建自签根 CA（Policy 选用途策略，默认 Web TLS；KeyType/KeyParams 可覆盖用于建 EC 根等）。允许多根。</summary>
        [HttpPost("InitRootCA")]
        public IActionResult InitRootCA([FromBody] InitRootCARequest req)
        {
            try
            {
                var r = CA_Service.CreateRoot(req?.Name, req?.Policy, req?.KeyType, req?.KeyParams);
                return IssueOk(r);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error generating Root CA certificate: " + ex.Message);
            }
        }

        /// <summary>
        /// 建 CA：
        /// - 传 CSR：按 CSR 密钥类型签发（必须与父同类型），ParentSerial 必填。
        /// - 无 CSR 且无父：按 Policy 新建根。
        /// - 无 CSR 且有父：服务端生成与父同类型密钥的下一级 CA。
        /// </summary>
        [HttpPost("CreateCA")]
        public IActionResult CreateCA([FromBody] CreateCARequest req)
        {
            try
            {
                if (req == null) return BadRequest("Invalid request data.");

                if (!string.IsNullOrEmpty(req.CSR))
                {
                    if (string.IsNullOrEmpty(req.ParentSerial))
                        return BadRequest("CSR-based CA creation requires ParentSerial.");
                    var r = CA_Service.CreateCAFromCSR(req.ParentSerial, req.CSR, req.Name);
                    return IssueOk(r);
                }

                if (string.IsNullOrEmpty(req.ParentSerial))
                {
                    var root = CA_Service.CreateRoot(req.Name, req.Policy, req.KeyType, req.KeyParams);
                    return IssueOk(root);
                }

                var ca = CA_Service.CreateCA(req.ParentSerial, req.Name, req.Policy);
                return IssueOk(ca);
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>兼容旧接口：在指定父 CA（默认首个根）下建二级 CA（服务端密钥）。</summary>
        [HttpPost("InitSubCA")]
        public IActionResult InitSubCA([FromBody] Layer2Request req)
        {
            try
            {
                string parent = req != null && !string.IsNullOrEmpty(req.CAName)
                    ? req.CAName
                    : CA_DB.GetRoot()?.Serial;
                if (parent == null)
                    return StatusCode(400, "No root CA exists and no parent serial given.");

                var r = CA_Service.CreateCA(parent, req?.Name, null);
                return IssueOk(r);
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>服务端自生成密钥的叶子签发（密钥类型跟随签发者，私钥落盘不返回）。IssuerSerial 为空默认取首个根。</summary>
        [HttpPost("GenWebServerCert")]
        public IActionResult GenWebServerCert([FromBody] WebServerCertRequest req)
        {
            try
            {
                if (req == null) return BadRequest("Invalid request data.");

                string issuer = !string.IsNullOrEmpty(req.IssuerSerial) ? req.IssuerSerial : CA_DB.GetRoot()?.Serial;
                if (issuer == null)
                    return StatusCode(400, "No root CA exists and no issuer serial given.");

                var r = CA_Service.IssueLeaf(issuer, req.Name, req.DNSNames);
                return IssueOk(r);
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>
        /// CSR 模式签发叶子：私钥由请求方自持，CA 只签公钥、不返回私钥。
        /// IssuerSerial 为空时按 CSR 密钥类型自动路由到同类型 CA。
        /// </summary>
        [HttpPost("SignCSR")]
        public IActionResult SignCSR([FromBody] SignCSRRequest req)
        {
            try
            {
                if (req == null || string.IsNullOrEmpty(req.CSR))
                    return BadRequest("CSR is required.");

                var r = CA_Service.IssueLeafFromCSR(req.IssuerSerial, req.CSR, req.Name, req.DNSNames);
                return IssueOk(r);
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>按序列号下载证书（PEM）。</summary>
        [HttpGet("certs/{serial}/crt")]
        [HttpGet("certs/{serial}/pem")]
        public IActionResult GetCertPEM(string serial)
        {
            var rec = CA_Service.GetCert(serial);
            if (rec == null || !F.Exists(rec.CertPath))
                return StatusCode(404, "Certificate not found: " + serial);
            return File(F.ReadAllBytes(rec.CertPath), "application/x-pem-file");
        }

        /// <summary>完整证书链（叶子在前 → 根在后）。</summary>
        [HttpGet("certs/{serial}/chain")]
        public IActionResult GetChainPEM(string serial)
        {
            var chain = CA_Service.GetChain(serial);
            if (chain.Count == 0)
                return StatusCode(404, "Certificate not found: " + serial);

            var sb = new StringBuilder();
            foreach (var c in chain)
            {
                if (F.Exists(c.CertPath))
                    sb.Append(F.ReadAllText(c.CertPath)).Append('\n');
            }
            return File(Encoding.UTF8.GetBytes(sb.ToString()), "application/x-pem-file");
        }

        /// <summary>吊销证书。</summary>
        [HttpPost("Revoke")]
        public IActionResult Revoke([FromBody] RevokeRequest req)
        {
            try
            {
                if (req == null || string.IsNullOrEmpty(req.Serial))
                    return BadRequest("Serial is required.");

                var rec = CA_Service.Revoke(req.Serial, req.Reason);
                return Ok(new
                {
                    serial = rec.Serial,
                    status = rec.Status,
                    revokeReason = rec.RevokeReason,
                    revokedAt = rec.RevokedAt
                });
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>指定 CA 的 CRL（列出它直接签发的已吊销证书）。</summary>
        [HttpGet("crl/{caSerial}")]
        public IActionResult GetCRL(string caSerial)
        {
            try
            {
                var crl = CA_Service.BuildCRL(caSerial);
                return File(crl, "application/x-pem-file");
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>列出全部证书记录（前端可按 issuerSerial 渲染 CA 树）。</summary>
        [HttpGet("list")]
        public IActionResult List()
        {
            var list = CA_DB.ListAll().Select(r => new
            {
                serial = r.Serial,
                kind = r.Kind,
                subject = r.Subject,
                subjectFields = CA_OidNames.ParseSubject(r.Subject),
                issuerSerial = r.IssuerSerial,
                isCA = r.IsCA,
                san = r.San,
                status = r.Status,
                keyType = r.KeyType,
                keyParams = r.KeyParams,
                policyId = r.PolicyId,
                notBefore = r.NotBefore,
                notAfter = r.NotAfter,
                revokedAt = r.RevokedAt,
                revokeReason = r.RevokeReason
            });
            return Ok(list);
        }

        /// <summary>列出全部签发策略。</summary>
        [HttpGet("policies")]
        public IActionResult Policies()
        {
            var list = CA_DB.ListPolicies().Select(p => new
            {
                id = p.Id,
                name = p.Name,
                keyType = p.KeyType,
                keyParams = p.KeyParams,
                signAlgo = p.SignAlgo,
                caValidityDays = p.CaValidityDays,
                leafValidityDays = p.LeafValidityDays,
                useAIA = p.UseAIA,
                keyUsage = p.KeyUsage,
                extUsageOids = p.ExtUsageOids,
                certType = p.CertType,
                validation = p.Validation,
                isInternal = p.Internal
            });
            return Ok(list);
        }

        /// <summary>新建签发策略。</summary>
        [HttpPost("policies")]
        public IActionResult CreatePolicy([FromBody] PolicyRequest req)
        {
            try
            {
                if (req == null || string.IsNullOrWhiteSpace(req.Name) || string.IsNullOrWhiteSpace(req.KeyType))
                    return BadRequest("name and keyType are required.");
                if (string.IsNullOrWhiteSpace(req.KeyParams))
                    return BadRequest("keyParams is required (RSA bit size or EC curve).");

                var p = new PolicyRecord
                {
                    Name = req.Name.Trim(),
                    KeyType = req.KeyType.Trim().ToUpperInvariant(),
                    KeyParams = req.KeyParams.Trim(),
                    SignAlgo = req.SignAlgo,
                    CaValidityDays = req.CaValidityDays ?? 1825,
                    LeafValidityDays = req.LeafValidityDays ?? 90,
                    UseAIA = req.UseAIA ?? true,
                    KeyUsage = req.KeyUsage,
                    ExtUsageOids = req.ExtUsageOids,
                    CertType = string.IsNullOrEmpty(req.CertType) ? "custom" : req.CertType.Trim(),
                    Validation = req.Validation,
                    Internal = req.Internal ?? false
                };
                var saved = CA_DB.InsertPolicy(p);
                return Ok(new { id = saved.Id, name = saved.Name });
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>更新签发策略（仅更新给定字段）。</summary>
        [HttpPut("policies/{id:long}")]
        public IActionResult UpdatePolicy(long id, [FromBody] PolicyRequest req)
        {
            try
            {
                if (req == null) return BadRequest("Invalid request data.");
                CA_DB.UpdatePolicy(id, req.Name, req.KeyType, req.KeyParams, req.SignAlgo,
                    req.CaValidityDays, req.LeafValidityDays, req.UseAIA, req.KeyUsage, req.ExtUsageOids,
                    req.CertType, req.Validation, req.Internal);
                var updated = CA_DB.GetPolicyById(id);
                return Ok(new { id = updated.Id, name = updated.Name });
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>删除签发策略（被证书记录引用时拒绝）。</summary>
        [HttpDelete("policies/{id:long}")]
        public IActionResult DeletePolicy(long id)
        {
            try
            {
                CA_DB.DeletePolicy(id);
                return Ok(new { deleted = id });
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        // ---------- OID 可读名（含自定义注册） ----------

        /// <summary>列出全部 OID 注册项（内置 + 自定义，自定义可覆盖内置名）。</summary>
        [HttpGet("oidnames")]
        public IActionResult ListOidNames()
        {
            try
            {
                return Ok(CA_OidNames.ListAll());
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>注册 / 覆盖 OID 可读名（允许自定义 OID 或覆盖内置名）。</summary>
        [HttpPost("oidnames")]
        public IActionResult UpsertOidName([FromBody] OidNameRequest req)
        {
            try
            {
                if (req == null || string.IsNullOrWhiteSpace(req.Oid) || string.IsNullOrWhiteSpace(req.Name))
                    return BadRequest("oid and name are required.");
                var rec = CA_DB.UpsertOidName(req.Oid, req.Name, req.Description);
                var builtIn = CA_OidNames.IsBuiltIn(rec.Oid);
                return Ok(new { oid = rec.Oid, name = rec.Name, description = rec.Description, builtIn });
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>删除自定义 OID 注册（若该 OID 内置，仅清除覆盖回退到内置名）。</summary>
        [HttpDelete("oidnames/{oid}")]
        public IActionResult DeleteOidName(string oid)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(oid)) return BadRequest("oid is required.");
                bool builtIn = CA_OidNames.IsBuiltIn(oid.Trim());
                CA_DB.DeleteOidName(oid);
                return Ok(new { deleted = oid.Trim(), revertedToBuiltIn = builtIn });
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>批量解析逗号分隔 OID 列表 → 可读名（供前端展示）。</summary>
        [HttpGet("oidnames/resolve")]
        public IActionResult ResolveOidNames([FromQuery] string oids)
        {
            try
            {
                var names = CA_OidNames.ResolveList(oids);
                var raw = string.IsNullOrWhiteSpace(oids)
                    ? Array.Empty<string>()
                    : oids.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).Where(x => x.Length > 0).ToArray();
                var pairs = new List<object>();
                for (int i = 0; i < raw.Length; i++)
                    pairs.Add(new { oid = raw[i], name = i < names.Length ? names[i] : raw[i] });
                return Ok(pairs);
            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        /// <summary>真实 OCSP 响应。签名主体为被查询证书的直接签发者。</summary>
        [HttpPost("/ocsp")]
        public async System.Threading.Tasks.Task<IActionResult> OCSP()
        {
            byte[] requestBytes;
            using (var ms = new MemoryStream())
            {
                await Request.Body.CopyToAsync(ms);
                requestBytes = ms.ToArray();
            }
            var resp = CA_Service.HandleOCSP(requestBytes);
            return File(resp, "application/ocsp-response");
        }

        // ---------- 兼容：旧固定名称下载（一律只返回证书，不返回任何私钥） ----------

        [HttpGet, Route("ca.cer"), Route("ca.crt"), Route("ca.pem"),
         Route("ca.key"), Route("ca.pfx"), Route("ca.p12"), Route("ca.der"), Route("ca.p7b")]
        public IActionResult GetRootCACerts()
        {
            var root = CA_DB.GetRoot();
            if (root == null || !F.Exists(root.CertPath))
                return StatusCode(404, "Root CA not initialized.");
            return File(F.ReadAllBytes(root.CertPath), "application/x-pem-file");
        }

        [HttpGet, Route("subca.crt"), Route("subca.pem")]
        public IActionResult GetSubCACerts()
        {
            var root = CA_DB.GetRoot();
            if (root == null)
                return StatusCode(404, "Root CA not initialized.");
            var sub = CA_DB.ListByIssuer(root.Serial).FirstOrDefault(c => c.IsCA);
            if (sub == null || !F.Exists(sub.CertPath))
                return StatusCode(404, "No Sub CA found.");
            return File(F.ReadAllBytes(sub.CertPath), "application/x-pem-file");
        }
    }
}
