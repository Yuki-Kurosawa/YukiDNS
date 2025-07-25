using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography.X509Certificates;

namespace YukiDNS.CA_CORE
{
    public class CA_Helper
    {
        public static void GenerateSelfSignCert(CA_Config config, string name, AsymmetricCipherKeyPair key)
        {
            Asn1SignatureFactory asn = new Asn1SignatureFactory(config.SignMethod, key.Private, new SecureRandom());
            var gen = new X509V3CertificateGenerator();
            gen.SetIssuerDN(new X509Name(name));
            gen.SetSubjectDN(new X509Name(name));
            gen.SetSerialNumber(new BigInteger("1"));
            gen.SetNotBefore(DateTime.Now.Date);
            gen.SetNotAfter(DateTime.Now.AddDays(config.SelfSignCACertExpire).Date);
            gen.SetPublicKey(key.Public);

            // extended information
            gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(key.Public));
            gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(key.Public));

            gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(
                new DerObjectIdentifier[] {
                    KeyPurposeID.id_kp_serverAuth,
                    KeyPurposeID.id_kp_clientAuth,
                    new DerObjectIdentifier("1.2.3.4.5.6")
                }));
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(3));
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.CrlSign | KeyUsage.KeyCertSign));


            if (config.AIAConfig.UseAIA)
            {

                GeneralName ocsp = new GeneralName(GeneralName.UniformResourceIdentifier, config.AIAConfig.OCSPMethod);
                GeneralName ci = new GeneralName(GeneralName.UniformResourceIdentifier, config.AIAConfig.CAIssuer);

                AuthorityInformationAccess aia = new AuthorityInformationAccess(new[]
                {
                    new AccessDescription(X509ObjectIdentifiers.OcspAccessMethod, ocsp) ,
                    new AccessDescription(X509ObjectIdentifiers.IdADCAIssuers, ci) ,
                });

                gen.AddExtension(X509Extensions.AuthorityInfoAccess, false, aia.ToAsn1Object());
            }

            var cert = gen.Generate(asn);

            StringBuilder pb = new StringBuilder();
            PemWriter pw = new PemWriter(new StringWriter(pb));
            pw.WriteObject(cert);
            string ca = pb.ToString();
            File.WriteAllText(config.CertDir + "ca.crt", ca);

            StringBuilder pb2 = new StringBuilder();
            PemWriter pw2 = new PemWriter(new StringWriter(pb2));
            pw2.WriteObject(key.Private);
            string ca2 = pb2.ToString();
            File.WriteAllText(config.CertDir + "ca.pem", ca2);

            var certEntry = new X509CertificateEntry(cert);
            var store = new Pkcs12StoreBuilder().Build();
            store.SetCertificateEntry("CERT", certEntry);   //设置证书  
            var chain = new X509CertificateEntry[1];
            chain[0] = certEntry;
            store.SetKeyEntry("CERT", new AsymmetricKeyEntry(key.Private), chain);   //设置私钥  
            SecureRandom random = new SecureRandom();
            using (var fs = File.Create(config.CertDir + "ca.pfx"))
            {
                store.Save(fs, "123456".ToCharArray(), random); //保存  
            }
            ;

            X509ExtensionsGenerator sg = new X509ExtensionsGenerator();
            X509Extensions sans = sg.Generate();
            Asn1Set asn1 = new DerSet(new AttributeX509(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(sans)));

            Pkcs10CertificationRequest request = new Pkcs10CertificationRequest("sha256withRSA", new X509Name(name), key.Public, asn1, key.Private);
            StringBuilder pb3 = new StringBuilder();
            PemWriter pw3 = new PemWriter(new StringWriter(pb3));
            pw3.WriteObject(request);
            string ca3 = pb3.ToString();
            File.WriteAllText(config.CertDir + "ca.csr", ca3);
        }

        public static void GenerateLayer2Cert(CA_Config config, string caname, string name, AsymmetricCipherKeyPair cakey, AsymmetricCipherKeyPair key)
        {
            Asn1SignatureFactory subasn = new Asn1SignatureFactory("SHA256withRSA", cakey.Private, new SecureRandom());


            var subgen = new X509V3CertificateGenerator();
            subgen.SetIssuerDN(new X509Name(caname));
            subgen.SetSubjectDN(new X509Name(name));
            subgen.SetSerialNumber(new BigInteger("2"));
            subgen.SetNotBefore(DateTime.Now.Date);
            subgen.SetNotAfter(DateTime.Now.AddDays(config.CACertExpire).Date);
            subgen.SetPublicKey(key.Public);

            // extended information
            subgen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(cakey.Public));
            subgen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(key.Public));

            subgen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(
                new DerObjectIdentifier[] {
                    KeyPurposeID.id_kp_serverAuth,
                    KeyPurposeID.id_kp_clientAuth,
                    new DerObjectIdentifier("1.2.3.4.5.6")
                }));
            subgen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(2));
            subgen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.CrlSign | KeyUsage.KeyCertSign));


            var subcert = subgen.Generate(subasn);

            StringBuilder subpb = new StringBuilder();
            PemWriter subpw = new PemWriter(new StringWriter(subpb));
            subpw.WriteObject(subcert);
            string subca = subpb.ToString();
            File.WriteAllText(config.CertDir + "subca.crt", subca);

            StringBuilder pb2 = new StringBuilder();
            PemWriter pw2 = new PemWriter(new StringWriter(pb2));
            pw2.WriteObject(key.Private);
            string ca2 = pb2.ToString();
            File.WriteAllText(config.CertDir + "subca.pem", ca2);
        }

        public static void GenerateWebServerCert(CA_Config config, string caname, string name, string dnsnames, AsymmetricCipherKeyPair cakey, AsymmetricCipherKeyPair key)
        {
            Asn1SignatureFactory subasn = new Asn1SignatureFactory("SHA256withRSA", cakey.Private, new SecureRandom());


            var subgen = new X509V3CertificateGenerator();
            subgen.SetIssuerDN(new X509Name(caname));
            subgen.SetSubjectDN(new X509Name(name));
            subgen.SetSerialNumber(new BigInteger("3"));
            subgen.SetNotBefore(DateTime.Now.Date);
            subgen.SetNotAfter(DateTime.Now.AddDays(config.EndUserCertExpire).Date);
            subgen.SetPublicKey(key.Public);

            // extended information
            subgen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(cakey.Public));
            subgen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(key.Public));

            subgen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(
                new DerObjectIdentifier[] {
                    KeyPurposeID.id_kp_serverAuth,
                    new DerObjectIdentifier("1.2.3.4.5.6")
                }));
            subgen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            subgen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));

            GeneralNames gns1 = null;

            List<GeneralName> gnsl = new List<GeneralName>();

            string[] dnsnamelist = dnsnames.Split(',');

            foreach (string dnsname in dnsnamelist)
            {
                if (!string.IsNullOrEmpty(dnsname.Trim()))
                {
                    gnsl.Add(new GeneralName(GeneralName.DnsName, dnsname.Trim()));
                }
            }

            //new GeneralNames(new GeneralName[] {
            //        new GeneralName(GeneralName.DnsName,"localhost"),
            //        new GeneralName(GeneralName.IPAddress,"127.0.0.1"),
            //        new GeneralName(GeneralName.IPAddress,"::1"),
            //        new GeneralName(GeneralName.Rfc822Name,"admin@test.root"),
            //        new GeneralName(GeneralName.Rfc822Name,"www@test.root"),
            //    });

            if (gnsl.Count > 0)
            {
                gns1 = new GeneralNames(gnsl.ToArray());
                subgen.AddExtension(X509Extensions.SubjectAlternativeName, false, gns1.ToAsn1Object());

            }

            var subcert = subgen.Generate(subasn);

            StringBuilder subpb = new StringBuilder();
            PemWriter subpw = new PemWriter(new StringWriter(subpb));
            subpw.WriteObject(subcert);
            string subca = subpb.ToString();
            File.WriteAllText(config.CertDir + "user.crt", subca);

            StringBuilder pb2 = new StringBuilder();
            PemWriter pw2 = new PemWriter(new StringWriter(pb2));
            pw2.WriteObject(key.Private);
            string ca2 = pb2.ToString();
            File.WriteAllText(config.CertDir + "user.pem", ca2);
        }


        public static X509Certificate2 LoadPEMCert(string certFile, string keyFile = null)
        {

            X509Certificate2 crt = X509Certificate2.CreateFromPemFile(certFile, keyFile);

            return crt;
        }
    }
}
