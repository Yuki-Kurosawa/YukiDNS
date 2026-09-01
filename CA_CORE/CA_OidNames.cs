using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace YukiDNS.CA_CORE
{
    /// <summary>
    /// OID → 用户可读名解析：自定义注册（oid_names 表）优先，其次内置常见 OID 映射，最后原样返回 OID。
    /// 用于把证书里的 EKU / 扩展 OID 转成可读文本，并支持用户注册自定义 OID。
    /// </summary>
    public static class CA_OidNames
    {
        // 内置常见 OID → 可读名。用户在后台新增/覆盖的自定义项存 DB，优先级高于这里。
        private static readonly Dictionary<string, (string Name, string Desc)> Builtin =
            new Dictionary<string, (string, string)>(StringComparer.Ordinal)
            {
                // ---------- ExtendedKeyUsage (1.3.6.1.5.5.7.3.*) ----------
                ["1.3.6.1.5.5.7.3.1"] = ("serverAuth", "TLS Web 服务器认证 (Server Authentication)"),
                ["1.3.6.1.5.5.7.3.2"] = ("clientAuth", "TLS Web 客户端认证 (Client Authentication)"),
                ["1.3.6.1.5.5.7.3.3"] = ("codeSigning", "代码签名 (Code Signing)"),
                ["1.3.6.1.5.5.7.3.4"] = ("emailProtection", "安全邮件 / S/MIME (Email Protection)"),
                ["1.3.6.1.5.5.7.3.5"] = ("ipsecEndSystem", "IPSec 端系统"),
                ["1.3.6.1.5.5.7.3.6"] = ("ipsecTunnel", "IPSec 隧道"),
                ["1.3.6.1.5.5.7.3.7"] = ("ipsecUser", "IPSec 用户"),
                ["1.3.6.1.5.5.7.3.8"] = ("timeStamping", "时间戳签名 (Time Stamping)"),
                ["1.3.6.1.5.5.7.3.9"] = ("OCSPSigning", "OCSP 响应签名 (OCSP Signing)"),
                ["1.3.6.1.5.5.7.3.10"] = ("dvcs", "DVCS (Data Validation)"),
                ["1.3.6.1.5.5.7.3.11"] = ("ipsecIKE", "IPSec IKE"),
                ["1.3.6.1.5.5.7.3.12"] = ("capwapAC", "CAPWAP AC"),
                ["1.3.6.1.5.5.7.3.13"] = ("capwapWTP", "CAPWAP WTP"),
                ["1.3.6.1.5.5.7.3.14"] = ("secureShellClient", "SSH 客户端"),
                ["1.3.6.1.5.5.7.3.15"] = ("secureShellServer", "SSH 服务器"),
                ["1.3.6.1.5.5.7.3.16"] = ("sendRouter", "SEND Router"),
                ["1.3.6.1.5.5.7.3.17"] = ("sendProxiedRouter", "SEND Proxied Router"),
                ["1.3.6.1.5.5.7.3.18"] = ("sendOwner", "SEND Owner"),
                ["1.3.6.1.5.5.7.3.19"] = ("sendProxiedOwner", "SEND Proxied Owner"),
                ["1.3.6.1.5.5.7.3.21"] = ("timestamping", "时间戳 (Timestamping)"),
                ["1.3.6.1.5.5.7.3.22"] = ("cmcCA", "CMC CA"),
                ["1.3.6.1.5.5.7.3.23"] = ("cmcRA", "CMC RA"),
                ["1.3.6.1.5.5.7.3.24"] = ("cmcArchive", "CMC Archive"),
                ["1.3.6.1.5.5.7.3.25"] = ("cmcUpdate", "CMC Update"),
                ["1.3.6.1.5.5.7.3.27"] = ("bgpsecRouter", "BGPsec Router"),
                ["1.3.6.1.5.5.7.3.28"] = ("bgpsecAS", "BGPsec AS"),
                ["2.5.29.37.0"] = ("anyExtendedKeyUsage", "任意扩展用途 (Any EKU)"),

                // ---------- 标准 X.509 扩展 (2.5.29.*) ----------
                ["2.5.29.14"] = ("subjectKeyIdentifier", "主体密钥标识 (Subject Key Identifier)"),
                ["2.5.29.15"] = ("keyUsage", "密钥用途 (Key Usage)"),
                ["2.5.29.16"] = ("privateKeyUsagePeriod", "私钥使用期 (Private Key Usage Period)"),
                ["2.5.29.17"] = ("subjectAltName", "主体备用名称 (Subject Alternative Name)"),
                ["2.5.29.18"] = ("issuerAltName", "签发者备用名称 (Issuer Alternative Name)"),
                ["2.5.29.19"] = ("basicConstraints", "基本约束 (Basic Constraints)"),
                ["2.5.29.21"] = ("crlReason", "吊销原因 (CRL Reason)"),
                ["2.5.29.30"] = ("nameConstraints", "名称约束 (Name Constraints)"),
                ["2.5.29.31"] = ("crlDistributionPoints", "CRL 分发点 (CRL Distribution Points)"),
                ["2.5.29.32"] = ("certificatePolicies", "证书策略 (Certificate Policies)"),
                ["2.5.29.33"] = ("policyMappings", "策略映射 (Policy Mappings)"),
                ["2.5.29.35"] = ("authorityKeyIdentifier", "签发者密钥标识 (Authority Key Identifier)"),
                ["2.5.29.36"] = ("policyConstraints", "策略约束 (Policy Constraints)"),
                ["2.5.29.37"] = ("extKeyUsage", "扩展用途 (Extended Key Usage)"),
                ["2.5.29.46"] = ("freshestCRL", "增量 CRL (Freshest CRL)"),
                ["2.5.29.54"] = ("inhibitAnyPolicy", "禁止任意策略 (Inhibit Any Policy)"),

                // ---------- CA/Browser Forum EV / 验证级策略 OID ----------
                ["2.23.140.1.1"] = ("evPolicy", "扩展验证 (EV) 证书策略"),
                ["2.23.140.1.2.1"] = ("evCodeSigning", "EV 代码签名策略"),
                ["2.23.140.1.2.2"] = ("evTlsServer", "EV TLS 服务器策略"),
                ["2.23.140.1.2.3"] = ("evTlsClient", "EV TLS 客户端策略"),
                ["2.23.140.1.3"] = ("evSmime", "EV S/MIME 策略"),
                ["2.23.140.1.2"] = ("ovTls", "OV/TLS 策略 (CA/B Forum)"),
                ["2.23.140.1.4.1"] = ("brTlsServer", "BR TLS 服务器 (TLS BR)"),
                ["2.23.140.1.4.2"] = ("brTlsClient", "BR TLS 客户端 (TLS BR)"),

                // ---------- 其他常用 ----------
                ["1.3.6.1.5.5.7.1.1"] = ("authorityInfoAccess", "签发者信息访问 (AIA: caIssuers / OCSP)"),
                ["1.3.6.1.5.5.7.1.11"] = ("subjectInfoAccess", "主体信息访问 (Subject Info Access)"),
                ["1.3.6.1.5.5.7.48.1"] = ("ocsp", "OCSP 端点"),
                ["1.3.6.1.5.5.7.48.2"] = ("caIssuers", "CA 签发者证书获取"),
                ["1.3.6.1.5.5.7.6.1"] = ("id_aa_signingCertificate", "签名证书属性 (Signing Certificate)"),
                ["1.3.6.1.5.5.7.6.2"] = ("smimeCapabilities", "S/MIME 能力 (SMIMECapabilities)"),

                // ---------- Subject / 公钥算法 ----------
                ["2.5.4.3"] = ("commonName", "通用名 (CN)"),
                ["2.5.4.4"] = ("surname", "姓氏 (SN)"),
                ["2.5.4.5"] = ("serialNumber", "序列号属性"),
                ["2.5.4.6"] = ("countryName", "国家 (C)"),
                ["2.5.4.7"] = ("localityName", "地区 (L)"),
                ["2.5.4.8"] = ("stateOrProvinceName", "省份 (ST)"),
                ["2.5.4.9"] = ("streetAddress", "街道地址"),
                ["2.5.4.10"] = ("organizationName", "组织 (O)"),
                ["2.5.4.11"] = ("organizationalUnitName", "部门 (OU)"),
                ["2.5.4.42"] = ("givenName", "名字 (GN)"),
                ["1.2.840.113549.1.9.1"] = ("emailAddress", "电子邮件地址"),
                ["0.9.2342.19200300.100.1.25"] = ("domainComponent", "域组件 (DC)"),
                ["1.2.840.113549.1.1.1"] = ("rsaEncryption", "RSA 公钥 (RSA)"),
                ["1.2.840.10045.2.1"] = ("id-ecPublicKey", "EC 公钥 (EC)"),
                ["1.2.840.10045.3.1.7"] = ("prime256v1", "曲线 P-256 (prime256v1)"),
                ["1.3.132.0.34"] = ("secp384r1", "曲线 P-384 (secp384r1)"),
                ["1.3.132.0.35"] = ("secp521r1", "曲线 P-521 (secp521r1)"),
            };

        /// <summary>解析单个 OID → 可读名。自定义注册优先，其次内置，最后原样返回 OID。</summary>
        public static string Resolve(string oid)
        {
            if (string.IsNullOrWhiteSpace(oid)) return oid ?? "";
            string o = oid.Trim();
            var custom = CA_DB.GetOidName(o);
            if (custom != null && !string.IsNullOrWhiteSpace(custom.Name)) return custom.Name;
            return Builtin.TryGetValue(o, out var b) ? b.Name : o;
        }

        /// <summary>解析逗号分隔的 OID 列表 → 可读名列表（元素顺序保持）。</summary>
        public static string[] ResolveList(string oidList)
        {
            if (string.IsNullOrWhiteSpace(oidList)) return Array.Empty<string>();
            return oidList.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim()).Where(x => x.Length > 0).Select(Resolve).ToArray();
        }

        /// <summary>该 OID 是否为内置映射（用于删除语义：内置项删除仅回退到内置名）。</summary>
        public static bool IsBuiltIn(string oid)
        {
            return !string.IsNullOrWhiteSpace(oid) && Builtin.ContainsKey(oid.Trim());
        }

        /// <summary>Subject 里的单个属性字段（OID + 可读名 + 值）。</summary>
        public class SubjectField
        {
            public string Oid { get; set; }
            public string Name { get; set; }
            public string Value { get; set; }
        }

        /// <summary>
        /// 把 X.500 Subject（RFC2253，如 "CN=www.example.com,O=MyOrg,C=JP"）解析成普通用户可读的字段列表。
        /// 解析失败（格式异常）返回空列表，由调用方回退到原始字符串展示。
        /// </summary>
        public static List<SubjectField> ParseSubject(string x500)
        {
            var result = new List<SubjectField>();
            if (string.IsNullOrWhiteSpace(x500)) return result;
            try
            {
                var name = new X509Name(x500);
                var oids = name.GetOidList();
                var vals = name.GetValueList();
                int n = Math.Min(oids.Count, vals.Count);
                for (int i = 0; i < n; i++)
                {
                    var oid = ((DerObjectIdentifier)oids[i]).Id;
                    var val = vals[i]?.ToString() ?? "";
                    result.Add(new SubjectField
                    {
                        Oid = oid,
                        Name = Resolve(oid),
                        Value = UnescapeX500(val)
                    });
                }
            }
            catch (Exception)
            {
                return new List<SubjectField>();
            }
            return result;
        }

        /// <summary>反转 X509Name 输出里的反斜杠转义（\, \+ \" \\ 等）。</summary>
        private static string UnescapeX500(string s)
        {
            if (string.IsNullOrEmpty(s) || s.IndexOf('\\') < 0) return s;
            var sb = new System.Text.StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '\\' && i + 1 < s.Length)
                {
                    sb.Append(s[i + 1]);
                    i++;
                }
                else
                {
                    sb.Append(s[i]);
                }
            }
            return sb.ToString();
        }

        /// <summary>返回全部 OID 注册项（内置 + 自定义合并；自定义覆盖同名内置）。</summary>
        public static List<OidNameRecord> ListAll()
        {
            var custom = CA_DB.ListCustomOidNames();
            var customByOid = custom.ToDictionary(x => x.Oid, StringComparer.Ordinal);

            var result = new List<OidNameRecord>();
            foreach (var kv in Builtin)
            {
                if (customByOid.TryGetValue(kv.Key, out var ov))
                {
                    result.Add(new OidNameRecord { Oid = kv.Key, Name = ov.Name, Description = ov.Description, BuiltIn = true });
                    customByOid.Remove(kv.Key);
                }
                else
                {
                    result.Add(new OidNameRecord { Oid = kv.Key, Name = kv.Value.Name, Description = kv.Value.Desc, BuiltIn = true });
                }
            }
            // 剩余自定义（非内置 OID）
            foreach (var kv in customByOid)
                result.Add(new OidNameRecord { Oid = kv.Value.Oid, Name = kv.Value.Name, Description = kv.Value.Description, BuiltIn = false });

            return result.OrderBy(x => x.Oid, StringComparer.Ordinal).ToList();
        }
    }
}
