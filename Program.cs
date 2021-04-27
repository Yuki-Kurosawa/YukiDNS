using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using YukiDNS.DNS_CORE;

namespace YukiDNS
{
    class Program
    {        

        static void Main(string[] args)
        {
            if (args[0] == "dns")
            {
                DNSService.Start();
            }
            else if (args[0] == "zone")
            {
                string[] data = File.ReadAllLines(@"test.zone");

                foreach (string line in data)
                {
                    Console.WriteLine(line);
                }
            }
            else
            {
                #region DO ROOT CA
                var keyr = new RSACryptoServiceProvider(2048);
                var key = DotNetUtilities.GetRsaKeyPair(keyr);
                Asn1SignatureFactory asn = new Asn1SignatureFactory("SHA256withRSA", key.Private, new SecureRandom());


                var gen = new X509V3CertificateGenerator();
                gen.SetIssuerDN(new X509Name("CN=TEST ROOT CA"));
                gen.SetSubjectDN(new X509Name("CN=TEST ROOT CA"));
                gen.SetSerialNumber(new BigInteger("1"));
                gen.SetNotBefore(DateTime.Now.Date);
                gen.SetNotAfter(DateTime.Now.AddDays(1).Date);
                gen.SetPublicKey(key.Public);

                // extended information
                gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(key.Public));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(key.Public));

                gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(
                    new DerObjectIdentifier[] {
                    KeyPurposeID.IdKPServerAuth,
                    KeyPurposeID.IdKPClientAuth,
                    new DerObjectIdentifier("1.2.3.4.5.6")
                    }));
                gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(3));
                gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.CrlSign | KeyUsage.KeyCertSign));


                var cert = gen.Generate(asn);

                StringBuilder pb = new StringBuilder();
                PemWriter pw = new PemWriter(new StringWriter(pb));
                pw.WriteObject(cert);
                string ca = pb.ToString();
                File.WriteAllText("1.ca.cer", ca);

                StringBuilder pb2 = new StringBuilder();
                PemWriter pw2 = new PemWriter(new StringWriter(pb2));
                pw2.WriteObject(key.Private);
                string ca2 = pb2.ToString();
                File.WriteAllText("1.ca.pem", ca2);

                var certEntry = new X509CertificateEntry(cert);
                var store = new Pkcs12StoreBuilder().Build();
                store.SetCertificateEntry("CERT", certEntry);   //设置证书  
                var chain = new X509CertificateEntry[1];
                chain[0] = certEntry;
                store.SetKeyEntry("CERT", new AsymmetricKeyEntry(key.Private), chain);   //设置私钥  
                SecureRandom random = new SecureRandom();
                using (var fs = File.Create("1.ca.pfx"))
                {
                    store.Save(fs, "".ToCharArray(), random); //保存  
                };

                X509ExtensionsGenerator sg = new X509ExtensionsGenerator();
                GeneralNames gns = new GeneralNames(new GeneralName[] {
                    new GeneralName(GeneralName.DnsName,"www.test.root"),
                    new GeneralName(GeneralName.DnsName,"test.root"),
                    new GeneralName(GeneralName.IPAddress,"127.0.0.1"),
                    new GeneralName(GeneralName.IPAddress,"::1"),
                    new GeneralName(GeneralName.Rfc822Name,"admin@test.root"),
                    new GeneralName(GeneralName.Rfc822Name,"www@test.root"),
                });
                sg.AddExtension(X509Extensions.SubjectAlternativeName, false, gns.ToAsn1Object());
                X509Extensions sans =sg.Generate();
                Asn1Set asn1 = new DerSet(new AttributeX509(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(sans)));

                Pkcs10CertificationRequest request = new Pkcs10CertificationRequest("sha256withRSA", new X509Name("CN=TEST ROOT CA"), key.Public, asn1, key.Private);
                StringBuilder pb3 = new StringBuilder();
                PemWriter pw3 = new PemWriter(new StringWriter(pb3));
                pw3.WriteObject(request);
                string ca3 = pb3.ToString();
                File.WriteAllText("1.ca.csr", ca3);

                #endregion

                #region DO SUB CA
                var subkeyr = new RSACryptoServiceProvider(2048);
                var subkey = DotNetUtilities.GetRsaKeyPair(subkeyr);
                Asn1SignatureFactory subasn = new Asn1SignatureFactory("SHA256withRSA", key.Private, new SecureRandom());


                var subgen = new X509V3CertificateGenerator();
                subgen.SetIssuerDN(new X509Name("CN=TEST ROOT CA"));
                subgen.SetSubjectDN(new X509Name("CN=TEST SUB CA"));
                subgen.SetSerialNumber(new BigInteger("2"));
                subgen.SetNotBefore(DateTime.Now.Date);
                subgen.SetNotAfter(DateTime.Now.AddDays(1).Date);
                subgen.SetPublicKey(subkey.Public);

                // extended information
                subgen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(key.Public));
                subgen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(subkey.Public));

                subgen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(
                    new DerObjectIdentifier[] {
                    KeyPurposeID.IdKPServerAuth,
                    KeyPurposeID.IdKPClientAuth,
                    new DerObjectIdentifier("1.2.3.4.5.6")
                    }));
                subgen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(2));
                subgen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.CrlSign | KeyUsage.KeyCertSign));


                var subcert = subgen.Generate(subasn);

                StringBuilder subpb = new StringBuilder();
                PemWriter subpw = new PemWriter(new StringWriter(subpb));
                subpw.WriteObject(subcert);
                string subca = subpb.ToString();
                File.WriteAllText("1.sub.cer", subca + ca);
                #endregion

                #region DO SUB SUB CA
                var subsubkeyr = new RSACryptoServiceProvider(2048);
                var subsubkey = DotNetUtilities.GetRsaKeyPair(subsubkeyr);
                Asn1SignatureFactory subsubasn = new Asn1SignatureFactory("SHA256withRSA", subkey.Private, new SecureRandom());


                var subsubgen = new X509V3CertificateGenerator();
                subsubgen.SetIssuerDN(new X509Name("CN=TEST SUB CA"));
                subsubgen.SetSubjectDN(new X509Name("CN=TEST SUB SUB CA"));
                subsubgen.SetSerialNumber(new BigInteger("3"));
                subsubgen.SetNotBefore(DateTime.Now.Date);
                subsubgen.SetNotAfter(DateTime.Now.AddDays(1).Date);
                subsubgen.SetPublicKey(subsubkey.Public);

                // extended information
                subsubgen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(subkey.Public));
                subsubgen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(subsubkey.Public));

                subsubgen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(
                    new DerObjectIdentifier[] {
                    KeyPurposeID.IdKPServerAuth,
                    KeyPurposeID.IdKPClientAuth,
                    new DerObjectIdentifier("1.2.3.4.5.6")
                    }));
                subsubgen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(1));
                subsubgen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.CrlSign | KeyUsage.KeyCertSign));


                var subsubcert = subsubgen.Generate(subsubasn);

                StringBuilder subsubpb = new StringBuilder();
                PemWriter subsubpw = new PemWriter(new StringWriter(subsubpb));
                subsubpw.WriteObject(subsubcert);
                string subsubca = subsubpb.ToString();
                File.WriteAllText("1.subsub.cer", subsubca + subca + ca);
                #endregion

                #region DO CERT
                var subsubsubkeyr = new RSACryptoServiceProvider(2048);
                var subsubsubkey = DotNetUtilities.GetRsaKeyPair(subsubsubkeyr);
                Asn1SignatureFactory subsubsubasn = new Asn1SignatureFactory("SHA256withRSA", subsubkey.Private, new SecureRandom());


                var subsubsubgen = new X509V3CertificateGenerator();
                subsubsubgen.SetIssuerDN(new X509Name("CN=TEST SUB SUB CA"));
                subsubsubgen.SetSubjectDN(new X509Name("CN=TEST CERT"));
                subsubsubgen.SetSerialNumber(new BigInteger("4"));
                subsubsubgen.SetNotBefore(DateTime.Now.Date);
                subsubsubgen.SetNotAfter(DateTime.Now.AddDays(1).Date);
                subsubsubgen.SetPublicKey(subsubsubkey.Public);

                // extended information
                subsubsubgen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(subsubkey.Public));
                subsubsubgen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(subsubsubkey.Public));

                subsubsubgen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(
                    new DerObjectIdentifier[] {
                    KeyPurposeID.IdKPServerAuth,
                    KeyPurposeID.IdKPClientAuth,
                    new DerObjectIdentifier("1.2.3.4.5.6")
                    }));
                subsubsubgen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
                subsubsubgen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));


                var subsubsubcert = subsubsubgen.Generate(subsubsubasn);

                StringBuilder subsubsubpb = new StringBuilder();
                PemWriter subsubsubpw = new PemWriter(new StringWriter(subsubsubpb));
                subsubsubpw.WriteObject(subsubsubcert);
                string subsubsubca = subsubsubpb.ToString();
                File.WriteAllText("1.user.cer", subsubsubca + subsubca + subca + ca);

                #endregion
            
            }
        }       
    }
}
