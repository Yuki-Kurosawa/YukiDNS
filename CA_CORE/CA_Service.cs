using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using X509 = Org.BouncyCastle.X509;

namespace YukiDNS.CA_CORE
{
    /// <summary>
    /// CA 业务门面：所有签发/吊销/CRL/OCSP 逻辑集中于此，HTTP Controller 与控制台共用。
    /// - 支持 RSA / EC 双密钥类型；同一条链必须同类型（RSA-RSA-RSA 或 EC-EC-EC）。
    /// - 签发策略存数据库 policies 表（可扩展），ca.json 只留服务级配置。
    /// - CSR 模式下私钥由请求方自持，CA 只签公钥、不落私钥、不返回私钥。
    /// </summary>
    public static class CA_Service
    {
        public static CA_Config config;
        private static bool _dbInit;

        public static void LoadConfig()
        {
            config = JsonConvert.DeserializeObject<CA_Config>(File.ReadAllText("conf/ca.json"));
            EnsureDB();
        }

        private static void EnsureDB()
        {
            if (!_dbInit)
            {
                CA_DB.Init(string.IsNullOrEmpty(config.Database) ? "certs/ca.db" : config.Database);
                _dbInit = true;
            }
        }

        private static string Url(string path)
        {
            if (string.IsNullOrEmpty(config.BaseURL)) return null;
            return config.BaseURL.TrimEnd('/') + "/" + path;
        }

        private static string[] ParseSANs(string dnsNames)
        {
            if (string.IsNullOrEmpty(dnsNames)) return new string[0];
            return dnsNames.Split(',')
                .Select(s => s.Trim())
                .Where(s => s.Length > 0)
                .ToArray();
        }

        // ---------- 策略 ----------

        private static PolicyRecord PolicyOf(CertRecord ca)
        {
            if (ca?.PolicyId.HasValue == true)
            {
                var p = CA_DB.GetPolicyById(ca.PolicyId.Value);
                if (p != null) return p;
            }
            return null;
        }

        /// <summary>取 CA 的策略；没有则回退 Web TLS（策略按用途划分，不按密钥类型）。</summary>
        private static PolicyRecord PolicyOrDefault(CertRecord ca)
        {
            var p = PolicyOf(ca);
            if (p != null) return p;
            return CA_DB.GetPolicyByName("Web TLS")
                ?? CA_DB.ListPolicies().FirstOrDefault()
                ?? throw new InvalidOperationException("No policy defined.");
        }

        private static PolicyRecord ResolvePolicy(string policyName)
        {
            if (string.IsNullOrEmpty(policyName)) return null;
            var p = long.TryParse(policyName, out var id) ? CA_DB.GetPolicyById(id) : CA_DB.GetPolicyByName(policyName);
            if (p == null) throw new InvalidOperationException("Policy not found: " + policyName);
            return p;
        }

        /// <summary>解析策略；策略按用途划分，密钥类型由链（父 CA / CSR）决定，不再强制与父匹配。</summary>
        private static PolicyRecord ResolvePolicyForCA(string policyName)
        {
            return ResolvePolicy(policyName);
        }

        private static string SignAlgoOf(PolicyRecord p, string keyType)
        {
            // 策略显式签名算法仅当其密钥类型与实际密钥类型一致时采用；否则按实际密钥类型推导
            if (p != null && !string.IsNullOrEmpty(p.SignAlgo)
                && string.Equals(p.KeyType, keyType, StringComparison.OrdinalIgnoreCase))
                return p.SignAlgo;
            return CA_Helper.DefaultSignAlgo(keyType);
        }

        private static bool UseAiaOf(PolicyRecord p)
        {
            return p == null || p.UseAIA;
        }

        // ---------- KeyUsage / EKU（策略决定证书用途） ----------

        /// <summary>默认 KeyUsage 位：CA 一律 keyCertSign|cRLSign；叶子按证书用途预设。</summary>
        private static int DefaultKeyUsageBits(PolicyRecord p, bool isCA)
        {
            if (isCA) return KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign;
            if (p?.CertType == "code-signing") return KeyUsage.DigitalSignature;
            if (p?.CertType == "email-client")
                return KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment;
            return KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment;
        }

        /// <summary>按策略 key_usage 位名列表解析 KeyUsage 掩码；CA 强制追加 KeyCertSign|CrlSign。</summary>
        private static int KeyUsageOf(PolicyRecord p, bool isCA)
        {
            string ku = p?.KeyUsage;
            int bits = 0;
            if (!string.IsNullOrWhiteSpace(ku))
            {
                foreach (var part in ku.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    switch (part.Trim().ToLowerInvariant())
                    {
                        case "digitalsignature": bits |= KeyUsage.DigitalSignature; break;
                        case "nonrepudiation": bits |= KeyUsage.NonRepudiation; break;
                        case "keyencipherment": bits |= KeyUsage.KeyEncipherment; break;
                        case "dataencipherment": bits |= KeyUsage.DataEncipherment; break;
                        case "keyagreement": bits |= KeyUsage.KeyAgreement; break;
                        case "keycertsign": bits |= KeyUsage.KeyCertSign; break;
                        case "crlsign": bits |= KeyUsage.CrlSign; break;
                        case "encipheronly": bits |= KeyUsage.EncipherOnly; break;
                        case "decipheronly": bits |= KeyUsage.DecipherOnly; break;
                    }
                }
            }
            if (bits == 0) bits = DefaultKeyUsageBits(p, isCA);
            if (isCA) bits |= KeyUsage.KeyCertSign | KeyUsage.CrlSign;
            return bits;
        }

        /// <summary>按策略 ext_usage_oids 解析 EKU OID 列表；EKU 仅用于叶子证书，CA 一律不设（RFC 5280）。
        /// 策略未配置 EKU 时，按证书用途类型给默认。</summary>
        private static string[] EkuOidsOf(PolicyRecord p, bool isCA)
        {
            if (isCA) return null;
            string eku = p?.ExtUsageOids;
            if (!string.IsNullOrWhiteSpace(eku))
                return eku.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).Where(x => x.Length > 0).ToArray();
            switch (p?.CertType)
            {
                case "email-client": return new[] { "1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.2" }; // emailProtection, clientAuth
                case "code-signing": return new[] { "1.3.6.1.5.5.7.3.3" };                      // codeSigning
                default: return new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" };             // serverAuth, clientAuth
            }
        }

        // ---------- 签发核心 ----------

        /// <summary>
        /// 统一签发：分配唯一序列号 → 构造证书 → 入库 → 落盘。
        /// keyPair 非空 = 服务端生成密钥（同时落私钥）；csrPublicKey 非空 = CSR 模式（只签公钥，不落私钥）。
        /// </summary>
        private static CertIssueResult Issue(
            string kind, string subject, string issuerSerial, bool isCA, string san,
            string keyType, string keyParams, long? policyId, int days,
            AsymmetricCipherKeyPair keyPair, AsymmetricKeyParameter csrPublicKey,
            Func<string, AsymmetricKeyParameter, X509.X509Certificate> build)
        {
            EnsureDB();
            DateTime nb = DateTime.UtcNow;
            DateTime na = nb.AddDays(days);
            for (int attempt = 0; attempt < 16; attempt++)
            {
                string serial = CA_DB.GenerateSerial();
                var cert = build(serial, csrPublicKey ?? keyPair.Public);

                var rec = new CertRecord
                {
                    Serial = serial,
                    Kind = kind,
                    Subject = subject,
                    IssuerSerial = issuerSerial,
                    IsCA = isCA,
                    San = san,
                    CertPath = Path.Combine(config.CertDir, serial + ".crt"),
                    KeyPath = keyPair != null ? Path.Combine(config.CertDir, serial + ".pem") : null,
                    NotBefore = nb,
                    NotAfter = na,
                    Status = "valid",
                    CreatedAt = nb,
                    KeyType = keyType,
                    KeyParams = keyParams,
                    PolicyId = policyId,
                };
                try
                {
                    CA_DB.Insert(rec);
                    CA_Helper.WritePEM(cert, rec.CertPath);
                    if (keyPair != null) CA_Helper.WritePEM(keyPair.Private, rec.KeyPath);
                    return new CertIssueResult { Record = rec, CertPEM = File.ReadAllText(rec.CertPath) };
                }
                catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
                {
                    // 序列号撞 UNIQUE，重试
                }
            }
            throw new InvalidOperationException("Unable to allocate a unique serial number.");
        }

        /// <summary>同类型链强制：链上所有证书密钥类型必须一致。</summary>
        private static void EnsureSameKeyType(CertRecord issuer, string keyType)
        {
            if (!string.Equals(issuer.KeyType, keyType, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "Key type mismatch: chains must be homogeneous (" + issuer.KeyType + "-chain, got " + keyType + " key).");
        }

        private static string SubjectFromCSR(Pkcs10CertificationRequest csr, string fallback)
        {
            try
            {
                var s = csr.GetCertificationRequestInfo().Subject;
                return s == null || string.IsNullOrEmpty(s.ToString()) ? fallback : s.ToString();
            }
            catch
            {
                return fallback;
            }
        }

        // ---------- 建根 ----------

        /// <summary>建自签根 CA。策略按用途选（如 Web TLS / 代码签名）；KeyType/KeyParams 可覆盖策略默认（用于建 EC 根等）。允许多个根，每棵独立信任树。</summary>
        public static CertIssueResult CreateRoot(string name, string policyName, string overrideKeyType = null, string overrideKeyParams = null)
        {
            EnsureDB();
            var policy = ResolvePolicy(policyName) ?? CA_DB.GetPolicyByName("Web TLS")
                ?? CA_DB.ListPolicies().FirstOrDefault()
                ?? throw new InvalidOperationException("No policy defined.");
            name = string.IsNullOrEmpty(name) ? config.DefaultSelfSignCAName : name;

            string keyType = string.IsNullOrEmpty(overrideKeyType) ? policy.KeyType : overrideKeyType;
            string keyParams = string.IsNullOrEmpty(overrideKeyParams) ? policy.KeyParams : overrideKeyParams;
            var key = CA_Helper.GenerateKeyForPolicy(keyType, keyParams);
            var signAlgo = SignAlgoOf(policy, keyType);

            return Issue("root", name, null, true, null,
                keyType, keyParams, policy.Id, policy.CaValidityDays, key, null,
                (serial, pub) => CA_Helper.GenerateCertificate(
                    signAlgo, UseAiaOf(policy),
                    issuerDN: name, issuerPublicKey: pub, signerKey: key,
                    subjectDN: name, serial: CA_DB.SerialToBigInteger(serial),
                    notBefore: DateTime.UtcNow, notAfter: DateTime.UtcNow.AddDays(policy.CaValidityDays),
                    subjectPublicKey: pub,
                    isCA: true, pathLenConstraint: -1, dnsNames: null,
                    keyUsage: KeyUsageOf(policy, true), ekuOids: EkuOidsOf(policy, true),
                    caIssuersUrl: null, ocspUrl: null, crlUrl: null));
        }

        // ---------- 建中间 CA ----------

        /// <summary>服务端生成与父 CA 同类型密钥的下一级 CA。policyName 指定用途策略（可省略继承父策略）。</summary>
        public static CertIssueResult CreateCA(string parentSerial, string name, string policyName)
        {
            EnsureDB();
            CertRecord parent = ResolveIssuer(parentSerial);
            if (!parent.IsCA) throw new InvalidOperationException("Issuer is not a CA: " + parent.Serial);

            var policy = ResolvePolicyForCA(policyName) ?? PolicyOrDefault(parent);
            name = string.IsNullOrEmpty(name) ? config.DefaultCAName : name;

            var key = CA_Helper.GenerateKeyForPolicy(parent.KeyType, parent.KeyParams);
            AsymmetricCipherKeyPair parentKey = CA_Helper.LoadKeyPair(parent.KeyPath);
            var signAlgo = SignAlgoOf(policy, parent.KeyType);

            return Issue("ca", name, parent.Serial, true, null,
                parent.KeyType, parent.KeyParams, policy.Id, policy.CaValidityDays, key, null,
                (serial, pub) => CA_Helper.GenerateCertificate(
                    signAlgo, UseAiaOf(policy),
                    issuerDN: parent.Subject, issuerPublicKey: parentKey.Public, signerKey: parentKey,
                    subjectDN: name, serial: CA_DB.SerialToBigInteger(serial),
                    notBefore: DateTime.UtcNow, notAfter: DateTime.UtcNow.AddDays(policy.CaValidityDays),
                    subjectPublicKey: pub,
                    isCA: true, pathLenConstraint: -1, dnsNames: null,
                    keyUsage: KeyUsageOf(policy, true), ekuOids: EkuOidsOf(policy, true),
                    caIssuersUrl: Url("CA/certs/" + parent.Serial + "/crt"),
                    ocspUrl: Url("ocsp"),
                    crlUrl: Url("CA/crl/" + parent.Serial)));
        }

        /// <summary>按 CSR 签发下一级 CA：密钥类型取 CSR 声明，必须与父 CA 同类型。</summary>
        public static CertIssueResult CreateCAFromCSR(string parentSerial, string csrPem, string name)
        {
            EnsureDB();
            CertRecord parent = ResolveIssuer(parentSerial);
            if (!parent.IsCA) throw new InvalidOperationException("Issuer is not a CA: " + parent.Serial);

            var csr = CA_Helper.LoadCSR(csrPem);
            var pub = csr.GetPublicKey();
            var keyType = CA_Helper.GetKeyType(pub);
            EnsureSameKeyType(parent, keyType);

            var policy = PolicyOrDefault(parent);
            name = string.IsNullOrEmpty(name) ? SubjectFromCSR(csr, config.DefaultCAName) : name;
            AsymmetricCipherKeyPair parentKey = CA_Helper.LoadKeyPair(parent.KeyPath);
            var signAlgo = SignAlgoOf(policy, parent.KeyType);

            return Issue("ca", name, parent.Serial, true, null,
                keyType, parent.KeyParams, policy.Id, policy.CaValidityDays, null, pub,
                (serial, spub) => CA_Helper.GenerateCertificate(
                    signAlgo, UseAiaOf(policy),
                    issuerDN: parent.Subject, issuerPublicKey: parentKey.Public, signerKey: parentKey,
                    subjectDN: name, serial: CA_DB.SerialToBigInteger(serial),
                    notBefore: DateTime.UtcNow, notAfter: DateTime.UtcNow.AddDays(policy.CaValidityDays),
                    subjectPublicKey: spub,
                    isCA: true, pathLenConstraint: -1, dnsNames: null,
                    keyUsage: KeyUsageOf(policy, true), ekuOids: EkuOidsOf(policy, true),
                    caIssuersUrl: Url("CA/certs/" + parent.Serial + "/crt"),
                    ocspUrl: Url("ocsp"),
                    crlUrl: Url("CA/crl/" + parent.Serial)));
        }

        // ---------- 签发叶子 ----------

        /// <summary>服务端生成与签发者同类型密钥的叶子证书。私钥落盘不返回。</summary>
        public static CertIssueResult IssueLeaf(string issuerSerial, string name, string dnsNames)
        {
            EnsureDB();
            CertRecord issuer = ResolveIssuer(issuerSerial);
            if (!issuer.IsCA) throw new InvalidOperationException("Issuer is not a CA: " + issuer.Serial);

            var policy = PolicyOrDefault(issuer);
            name = string.IsNullOrEmpty(name) ? config.DefaultEndUserName : name;
            string[] sans = ParseSANs(dnsNames);

            var key = CA_Helper.GenerateKeyForPolicy(issuer.KeyType, issuer.KeyParams);
            AsymmetricCipherKeyPair issuerKey = CA_Helper.LoadKeyPair(issuer.KeyPath);
            var signAlgo = SignAlgoOf(policy, issuer.KeyType);

            return Issue("leaf", name, issuer.Serial, false, dnsNames,
                issuer.KeyType, issuer.KeyParams, policy.Id, policy.LeafValidityDays, key, null,
                (serial, pub) => CA_Helper.GenerateCertificate(
                    signAlgo, UseAiaOf(policy),
                    issuerDN: issuer.Subject, issuerPublicKey: issuerKey.Public, signerKey: issuerKey,
                    subjectDN: name, serial: CA_DB.SerialToBigInteger(serial),
                    notBefore: DateTime.UtcNow, notAfter: DateTime.UtcNow.AddDays(policy.LeafValidityDays),
                    subjectPublicKey: pub,
                    isCA: false, pathLenConstraint: -1, dnsNames: sans,
                    keyUsage: KeyUsageOf(policy, false), ekuOids: EkuOidsOf(policy, false),
                    caIssuersUrl: Url("CA/certs/" + issuer.Serial + "/crt"),
                    ocspUrl: Url("ocsp"),
                    crlUrl: Url("CA/crl/" + issuer.Serial)));
        }

        /// <summary>
        /// CSR 模式签发叶子：密钥由请求方自持，CA 只签公钥。
        /// issuerSerial 为空时按 CSR 密钥类型自动路由到同类型 CA。
        /// </summary>
        public static CertIssueResult IssueLeafFromCSR(string issuerSerial, string csrPem, string name, string dnsNames)
        {
            EnsureDB();
            var csr = CA_Helper.LoadCSR(csrPem);
            var pub = csr.GetPublicKey();
            var keyType = CA_Helper.GetKeyType(pub);

            CertRecord issuer = string.IsNullOrEmpty(issuerSerial)
                ? FindIssuerByKeyType(keyType)
                : ResolveIssuer(issuerSerial);
            if (!issuer.IsCA) throw new InvalidOperationException("Issuer is not a CA: " + issuer.Serial);
            EnsureSameKeyType(issuer, keyType);

            var policy = PolicyOrDefault(issuer);
            name = string.IsNullOrEmpty(name) ? SubjectFromCSR(csr, config.DefaultEndUserName) : name;
            string[] sans = ParseSANs(dnsNames);
            if (sans.Length == 0) sans = CA_Helper.ExtractCSRSANs(csr);

            AsymmetricCipherKeyPair issuerKey = CA_Helper.LoadKeyPair(issuer.KeyPath);
            var signAlgo = SignAlgoOf(policy, issuer.KeyType);

            return Issue("leaf", name, issuer.Serial, false, string.Join(",", sans),
                keyType, issuer.KeyParams, policy.Id, policy.LeafValidityDays, null, pub,
                (serial, spub) => CA_Helper.GenerateCertificate(
                    signAlgo, UseAiaOf(policy),
                    issuerDN: issuer.Subject, issuerPublicKey: issuerKey.Public, signerKey: issuerKey,
                    subjectDN: name, serial: CA_DB.SerialToBigInteger(serial),
                    notBefore: DateTime.UtcNow, notAfter: DateTime.UtcNow.AddDays(policy.LeafValidityDays),
                    subjectPublicKey: spub,
                    isCA: false, pathLenConstraint: -1, dnsNames: sans,
                    keyUsage: KeyUsageOf(policy, false), ekuOids: EkuOidsOf(policy, false),
                    caIssuersUrl: Url("CA/certs/" + issuer.Serial + "/crt"),
                    ocspUrl: Url("ocsp"),
                    crlUrl: Url("CA/crl/" + issuer.Serial)));
        }

        /// <summary>按密钥类型自动选择签发者（最早创建的同类型 CA）。</summary>
        public static CertRecord FindIssuerByKeyType(string keyType)
        {
            EnsureDB();
            foreach (var rec in CA_DB.ListAll()
                .Where(c => c.IsCA && string.Equals(c.KeyType, keyType, StringComparison.OrdinalIgnoreCase))
                .OrderBy(c => c.Id))
                return rec;
            throw new InvalidOperationException("No CA with key type " + keyType + " exists. Create one first.");
        }

        // ---------- 查询 / 吊销 ----------

        /// <summary>解析签发者：必须显式给出序列号（多根/多分支下不存在隐式默认）。</summary>
        private static CertRecord ResolveIssuer(string issuerSerial)
        {
            if (string.IsNullOrEmpty(issuerSerial))
                throw new InvalidOperationException("Issuer serial is required (multiple CAs may exist).");
            CertRecord issuer = CA_DB.GetBySerial(issuerSerial);
            if (issuer == null)
                throw new InvalidOperationException("Issuer CA not found.");
            return issuer;
        }

        public static CertRecord GetCert(string serial)
        {
            EnsureDB();
            return CA_DB.GetBySerial(serial);
        }

        /// <summary>叶子在前的完整链（叶子 → … → 根）。</summary>
        public static List<CertRecord> GetChain(string serial)
        {
            EnsureDB();
            var chain = new List<CertRecord>();
            var seen = new HashSet<string>();
            var cur = CA_DB.GetBySerial(serial);
            while (cur != null && seen.Add(cur.Serial))
            {
                chain.Add(cur);
                cur = string.IsNullOrEmpty(cur.IssuerSerial) ? null : CA_DB.GetBySerial(cur.IssuerSerial);
            }
            return chain;
        }

        /// <summary>吊销证书（root 本身不允许吊销，避免整个链失效）。</summary>
        public static CertRecord Revoke(string serial, string reason)
        {
            EnsureDB();
            var rec = CA_DB.GetBySerial(serial);
            if (rec == null)
                throw new InvalidOperationException("Certificate not found: " + serial);
            if (rec.Kind == "root")
                throw new InvalidOperationException("Cannot revoke the root CA certificate.");

            CA_DB.Revoke(rec.Serial, reason);
            return CA_DB.GetBySerial(rec.Serial);
        }

        // ---------- CRL ----------

        /// <summary>生成指定 CA 的 CRL（PEM 字节），仅列出它直接签发的已吊销证书。RSA/EC 均可签名。</summary>
        public static byte[] BuildCRL(string caSerial)
        {
            EnsureDB();
            CertRecord ca = ResolveIssuer(caSerial);
            if (!ca.IsCA)
                throw new InvalidOperationException("Not a CA: " + ca.Serial);

            AsymmetricCipherKeyPair caKey = CA_Helper.LoadKeyPair(ca.KeyPath);
            var revoked = CA_DB.ListByIssuer(ca.Serial)
                .Where(r => r.Status == "revoked" && r.RevokedAt.HasValue)
                .ToList();

            var gen = new X509.X509V2CrlGenerator();
            gen.SetIssuerDN(new X509Name(ca.Subject));
            DateTime now = DateTime.UtcNow;
            gen.SetThisUpdate(now);
            gen.SetNextUpdate(now.AddDays(30));
            gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(caKey.Public));
            gen.AddExtension(X509Extensions.CrlNumber, false,
                new CrlNumber(BigInteger.ValueOf(1 + revoked.Count)));

            foreach (var r in revoked)
            {
                gen.AddCrlEntry(CA_DB.SerialToBigInteger(r.Serial), r.RevokedAt.Value, CrlReason.Unspecified);
            }

            var signAlgo = CA_Helper.DefaultSignAlgo(ca.KeyType);
            var sig = new Asn1SignatureFactory(signAlgo, caKey.Private, new SecureRandom());
            var crl = gen.Generate(sig);
            return Encoding.UTF8.GetBytes(CA_Helper.ToPEM(crl));
        }

        // ---------- OCSP ----------

        /// <summary>
        /// 真实 OCSP：按请求里的序列号查库 → 用「直接签发者」私钥签名（RSA/EC 均支持）→ Good / Revoked / Unknown。
        /// </summary>
        public static byte[] HandleOCSP(byte[] requestBytes)
        {
            EnsureDB();
            OcspReq ocspReq;
            try
            {
                ocspReq = new OcspReq(requestBytes);
            }
            catch
            {
                var errGen = new OCSPRespGenerator();
                return errGen.Generate((int)OcspRespStatus.MalformedRequest, null).GetEncoded();
            }

            Req singleRequest = ocspReq.GetRequestList()[0];
            CertificateID certId = singleRequest.GetCertID();
            BigInteger reqSerial = certId.SerialNumber;

            CertificateStatus status;
            X509.X509Certificate responderCert = null;
            AsymmetricCipherKeyPair responderKey = null;

            CertRecord cert = CA_DB.GetBySerial(CA_DB.BigIntegerToSerial(reqSerial));
            if (cert == null)
            {
                status = new UnknownStatus();
            }
            else if (cert.Status == "revoked")
            {
                DateTime revokedAt = cert.RevokedAt ?? DateTime.UtcNow;
                status = new RevokedStatus(revokedAt, CrlReason.Unspecified);
                responderCert = LoadIssuerCert(cert);
                responderKey = LoadIssuerKey(cert);
            }
            else
            {
                status = CertificateStatus.Good;
                responderCert = LoadIssuerCert(cert);
                responderKey = LoadIssuerKey(cert);
            }

            if (responderKey == null)
            {
                var errGen = new OCSPRespGenerator();
                return errGen.Generate((int)OcspRespStatus.TryLater, null).GetEncoded();
            }

            var basicGen = new BasicOcspRespGenerator(responderKey.Public);
            basicGen.AddResponse(certId, status);

            var clientExtensions = ocspReq.RequestExtensions;
            if (clientExtensions != null)
            {
                var nonce = clientExtensions.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
                if (nonce != null)
                {
                    basicGen.SetResponseExtensions(new X509Extensions(
                        new Dictionary<DerObjectIdentifier, X509Extension>
                        {
                            { OcspObjectIdentifiers.PkixOcspNonce, nonce }
                        }));
                }
            }

            X509.X509Certificate[] chain = { responderCert };
            var responderSignAlgo = CA_Helper.DefaultSignAlgo(CA_DB.GetBySerial(cert.IssuerSerial)?.KeyType ?? "RSA");
            var basicResp = basicGen.Generate(responderSignAlgo, responderKey.Private, chain, DateTime.UtcNow);

            var rg = new OCSPRespGenerator();
            var rr = rg.Generate((int)OcspResponseStatus.Successful, basicResp);
            return rr.GetEncoded();
        }

        private static X509.X509Certificate LoadIssuerCert(CertRecord cert)
        {
            if (string.IsNullOrEmpty(cert.IssuerSerial)) return null;
            CertRecord issuer = CA_DB.GetBySerial(cert.IssuerSerial);
            return issuer == null ? null : CA_Helper.LoadPEMCert(issuer.CertPath);
        }

        private static AsymmetricCipherKeyPair LoadIssuerKey(CertRecord cert)
        {
            if (string.IsNullOrEmpty(cert.IssuerSerial)) return null;
            CertRecord issuer = CA_DB.GetBySerial(cert.IssuerSerial);
            return issuer == null ? null : CA_Helper.LoadKeyPair(issuer.KeyPath);
        }

        // ---------- 控制台工具 ----------

        public static void Main(string[] args)
        {
            LoadConfig();
            Console.WriteLine("Yuki Certificate Authority");
            Console.WriteLine("1. Generate Root CA (RSA/EC by policy)");
            Console.WriteLine("2. Generate Layer-2 CA (under root, server-key)");
            Console.WriteLine("3. Generate Web Server Certificate (server-key)");
            Console.WriteLine("4. Generate CA under arbitrary parent (by serial, server-key)");
            Console.WriteLine("5. Issue leaf under arbitrary CA (by serial, server-key)");
            Console.WriteLine("6. Sign a leaf CSR");
            Console.WriteLine("7. Revoke certificate");
            Console.WriteLine("0. Exit");
            Console.Write("Please Input Your Choice: ");
            string input = Console.ReadLine();
            try
            {
                switch (input)
                {
                    case "1":
                        Console.Write("Name (X509, enter for default): ");
                        string n1 = Console.ReadLine();
                        Console.Write("Policy (RSA/EC, default RSA): ");
                        string pol = Console.ReadLine();
                        Console.WriteLine("Serial: " + CreateRoot(n1, string.IsNullOrEmpty(pol) ? "RSA" : pol).Record.Serial);
                        break;
                    case "2":
                        {
                            var root = CA_DB.GetRoot();
                            if (root == null) throw new InvalidOperationException("No root CA exists.");
                            Console.Write("Name (X509, enter for default): ");
                            Console.WriteLine("Serial: " + CreateCA(root.Serial, Console.ReadLine(), null).Record.Serial);
                        }
                        break;
                    case "3":
                        {
                            var root = CA_DB.GetRoot();
                            if (root == null) throw new InvalidOperationException("No root CA exists.");
                            Console.Write("Name (X509, enter for default): ");
                            string n3 = Console.ReadLine();
                            Console.Write("SANs (comma separated): ");
                            string san3 = Console.ReadLine();
                            Console.WriteLine("Serial: " + IssueLeaf(root.Serial, n3, san3).Record.Serial);
                        }
                        break;
                    case "4":
                        Console.Write("Parent CA serial: ");
                        string ps4 = Console.ReadLine();
                        Console.Write("Name (X509, enter for default): ");
                        Console.WriteLine("Serial: " + CreateCA(ps4, Console.ReadLine(), null).Record.Serial);
                        break;
                    case "5":
                        Console.Write("Issuer CA serial: ");
                        string is5 = Console.ReadLine();
                        Console.Write("Name (X509, enter for default): ");
                        string n5 = Console.ReadLine();
                        Console.Write("SANs (comma separated): ");
                        string san5 = Console.ReadLine();
                        Console.WriteLine("Serial: " + IssueLeaf(is5, n5, san5).Record.Serial);
                        break;
                    case "6":
                        Console.Write("CSR file path: ");
                        string csrPath = Console.ReadLine();
                        Console.Write("Issuer serial (empty = auto by key type): ");
                        string iss6 = Console.ReadLine();
                        var csrText = File.ReadAllText(csrPath);
                        var r6 = IssueLeafFromCSR(string.IsNullOrEmpty(iss6) ? null : iss6, csrText, null, null);
                        Console.WriteLine("Serial: " + r6.Record.Serial + " (key stays with requester)");
                        break;
                    case "7":
                        Console.Write("Serial to revoke: ");
                        string rs7 = Console.ReadLine();
                        Console.Write("Reason: ");
                        Revoke(rs7, Console.ReadLine());
                        Console.WriteLine("Revoked.");
                        break;
                    case "0":
                        return;
                    default:
                        Console.WriteLine("Unknown choice.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }
    }
}
