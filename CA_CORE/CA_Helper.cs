using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace YukiDNS.CA_CORE
{
    /// <summary>
    /// 证书构造工具：RSA / EC 通用。
    /// - 密钥生成、密钥类型判定（RSA / EC）
    /// - 通用签发（任意层级、AIA/CDP 按「直接签发者」传入，天然支持任意深度同类型链）
    /// - CSR（PKCS#10）解析：取 subject / 公钥 / 请求的 SAN
    /// </summary>
    public static class CA_Helper
    {
        public const string KeyTypeRSA = "RSA";
        public const string KeyTypeEC = "EC";

        /// <summary>按密钥类型推导默认签名算法。</summary>
        public static string DefaultSignAlgo(string keyType)
        {
            return keyType == KeyTypeEC ? "SHA256withECDSA" : "SHA256withRSA";
        }

        // ---------- 密钥生成 ----------

        public static AsymmetricCipherKeyPair GenerateRsaKey(int keySize)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);
            return DotNetUtilities.GetRsaKeyPair(rsa);
        }

        public static AsymmetricCipherKeyPair GenerateEcKey(string curveName)
        {
            if (string.IsNullOrEmpty(curveName)) curveName = "P-256";
            var x9 = ECNamedCurveTable.GetByName(curveName);
            if (x9 == null) throw new InvalidOperationException("Unknown EC curve: " + curveName);
            var domain = new ECDomainParameters(x9);
            var gen = new ECKeyPairGenerator();
            gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            return gen.GenerateKeyPair();
        }

        /// <summary>按策略生成密钥对。</summary>
        public static AsymmetricCipherKeyPair GenerateKeyForPolicy(string keyType, string keyParams)
        {
            if (keyType == KeyTypeEC) return GenerateEcKey(keyParams);
            int size = int.TryParse(keyParams, out var s) && s >= 1024 ? s : 2048;
            return GenerateRsaKey(size);
        }

        /// <summary>判定密钥类型：RSA | EC。</summary>
        public static string GetKeyType(AsymmetricKeyParameter key)
        {
            if (key is RsaKeyParameters) return KeyTypeRSA;
            if (key is ECKeyParameters) return KeyTypeEC;
            throw new InvalidOperationException("Unsupported key type: " + key.GetType().Name);
        }

        // ---------- 通用签发 ----------

        /// <summary>
        /// <summary>
        /// 通用签发：issuer 与 subject 相同即为自签（root）。
        /// signAlgo 按签发者密钥类型传入（RSA→SHA256withRSA，EC→SHA256withECDSA）。
        /// keyUsage 为 KeyUsage 位掩码；isCA=true 时强制追加 KeyCertSign|CrlSign。
        /// ekuOids 为 ExtendedKeyUsage OID 字符串列表，null/空 = 不设 EKU。
        /// </summary>
        public static Org.BouncyCastle.X509.X509Certificate GenerateCertificate(
            string signAlgo,
            bool useAia,
            string issuerDN,
            AsymmetricKeyParameter issuerPublicKey,
            AsymmetricCipherKeyPair signerKey,
            string subjectDN,
            BigInteger serial,
            DateTime notBefore,
            DateTime notAfter,
            AsymmetricKeyParameter subjectPublicKey,
            bool isCA,
            int pathLenConstraint,      // -1 = 不限制（root 常用），CA 传 >=0，叶子忽略
            string[] dnsNames,          // 仅叶子
            int keyUsage,               // KeyUsage 位掩码
            string[] ekuOids,           // EKU OID 列表（null = 不设）
            string caIssuersUrl,        // AIA.CAIssuers：签发者证书下载地址；root 为 null
            string ocspUrl,             // AIA.OCSP 地址
            string crlUrl)              // CDP：签发者 CRL 地址；root 为 null
        {
            var asn = new Asn1SignatureFactory(signAlgo, signerKey.Private, new SecureRandom());
            var gen = new X509V3CertificateGenerator();
            gen.SetIssuerDN(new X509Name(issuerDN));
            gen.SetSubjectDN(new X509Name(subjectDN));
            gen.SetSerialNumber(serial);
            gen.SetNotBefore(notBefore);
            gen.SetNotAfter(notAfter);
            gen.SetPublicKey(subjectPublicKey);

            gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuerPublicKey));
            gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(subjectPublicKey));

            if (isCA)
            {
                gen.AddExtension(X509Extensions.BasicConstraints, true,
                    pathLenConstraint >= 0 ? new BasicConstraints(pathLenConstraint) : new BasicConstraints(true));
                // CA 必须能签证书与 CRL，策略位之上强制追加
                gen.AddExtension(X509Extensions.KeyUsage, true,
                    new KeyUsage(keyUsage | KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            }
            else
            {
                gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
                gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(keyUsage));
            }

            if (ekuOids != null && ekuOids.Length > 0)
            {
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(
                    ekuOids.Select(o => new DerObjectIdentifier(o.Trim())).ToArray()));
            }

            if (!isCA && dnsNames != null && dnsNames.Length > 0)
            {
                var gnsl = new List<GeneralName>();
                foreach (var dn in dnsNames)
                    gnsl.Add(new GeneralName(GeneralName.DnsName, dn));
                gen.AddExtension(X509Extensions.SubjectAlternativeName, false,
                    new GeneralNames(gnsl.ToArray()).ToAsn1Object());
            }

            if (useAia)
            {
                var access = new List<AccessDescription>();
                if (!string.IsNullOrEmpty(ocspUrl))
                    access.Add(new AccessDescription(X509ObjectIdentifiers.OcspAccessMethod,
                        new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl)));
                if (!string.IsNullOrEmpty(caIssuersUrl))
                    access.Add(new AccessDescription(X509ObjectIdentifiers.IdADCAIssuers,
                        new GeneralName(GeneralName.UniformResourceIdentifier, caIssuersUrl)));
                if (access.Count > 0)
                    gen.AddExtension(X509Extensions.AuthorityInfoAccess, false,
                        new AuthorityInformationAccess(access.ToArray()).ToAsn1Object());

                if (!string.IsNullOrEmpty(crlUrl))
                {
                    var cdp = new CrlDistPoint(new DistributionPoint[] {
                        new DistributionPoint(
                            new DistributionPointName(new GeneralNames(
                                new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))),
                            null, null)
                    });
                    gen.AddExtension(X509Extensions.CrlDistributionPoints, false, cdp.ToAsn1Object());
                }
            }

            return gen.Generate(asn);
        }

        // ---------- PEM / 密钥加载 ----------

        public static void WritePEM(object o, string path)
        {
            var sb = new StringBuilder();
            var pw = new PemWriter(new StringWriter(sb));
            pw.WriteObject(o);
            pw.Writer.Flush();
            File.WriteAllText(path, sb.ToString());
        }

        public static string ToPEM(object o)
        {
            var sb = new StringBuilder();
            var pw = new PemWriter(new StringWriter(sb));
            pw.WriteObject(o);
            pw.Writer.Flush();
            return sb.ToString();
        }

        /// <summary>加载 RSA 或 EC 私钥（兼容 PKCS#1 / SEC1 / PKCS#8 密钥对多种写法）。</summary>
        public static AsymmetricCipherKeyPair LoadKeyPair(string pemPath)
        {
            object obj;
            using (var sr = new StreamReader(pemPath))
            {
                obj = new PemReader(sr).ReadObject();
            }

            if (obj is AsymmetricCipherKeyPair kp)
                return kp;

            if (obj is RsaPrivateCrtKeyParameters rp)
            {
                var pub = new RsaKeyParameters(false, rp.Modulus, rp.PublicExponent);
                return new AsymmetricCipherKeyPair(pub, rp);
            }

            if (obj is ECPrivateKeyParameters ep)
            {
                var q = ep.Parameters.G.Multiply(ep.D).Normalize();
                var pub = new ECPublicKeyParameters(ep.AlgorithmName, q, ep.Parameters);
                return new AsymmetricCipherKeyPair(pub, ep);
            }

            throw new InvalidOperationException("Unsupported private key format: " + pemPath);
        }

        public static Org.BouncyCastle.X509.X509Certificate LoadPEMCert(string certPath)
        {
            using var sr = new StreamReader(certPath);
            return (Org.BouncyCastle.X509.X509Certificate)new PemReader(sr).ReadObject();
        }

        /// <summary>兼容旧调用：证书 + 私钥文件加载为 .NET 对象（供 DNS/TLS 等服务使用）。</summary>
        public static X509Certificate2 LoadPEMCert(string certFile, string keyFile = null)
        {
            return X509Certificate2.CreateFromPemFile(certFile, keyFile);
        }

        // ---------- CSR（PKCS#10） ----------

        public static Pkcs10CertificationRequest LoadCSR(string pem)
        {
            if (string.IsNullOrEmpty(pem)) throw new InvalidOperationException("CSR is empty.");
            object obj;
            using (var sr = new StringReader(pem.Trim()))
            {
                obj = new PemReader(sr).ReadObject();
            }
            if (obj is Pkcs10CertificationRequest csr) return csr;
            throw new InvalidOperationException("Not a valid PKCS#10 CSR.");
        }

        /// <summary>提取 CSR 中请求的 SAN（DNS/IP），没有则返回空数组。</summary>
        public static string[] ExtractCSRSANs(Pkcs10CertificationRequest csr)
        {
            var exts = csr.GetRequestedExtensions();
            if (exts == null) return new string[0];
            var san = exts.GetExtension(X509Extensions.SubjectAlternativeName);
            if (san == null) return new string[0];
            var names = GeneralNames.GetInstance(san.GetParsedValue());
            var list = new List<string>();
            foreach (var gn in names.GetNames())
            {
                if (gn.TagNo == GeneralName.DnsName) list.Add(gn.Name.ToString());
                else if (gn.TagNo == GeneralName.IPAddress) list.Add(gn.Name.ToString());
            }
            return list.ToArray();
        }
    }
}
