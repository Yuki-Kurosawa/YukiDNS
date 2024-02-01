using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
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
using Newtonsoft.Json;

namespace YukiDNS.CA_CORE
{
    public class CA_Service
    {
        public static CA_Config config;

        public static void Main(string[] args)
        {
            LoadConfig();

            Console.WriteLine("Yuki Certificate Authority 0.1.4");
            Console.WriteLine("1. Generate Self Signed Root CA Certificate");
            Console.WriteLine("2. Generate Layer-2 CA Certificate");
            Console.WriteLine("3. Generate Web Server Certificate");
            Console.WriteLine("0. Exit");
            Console.Write("Please Input Your Choice: ");
            string input = Console.ReadLine();
            switch (input)
            {
                case "1": GenerateSelfSign(); break;
                case "2": GenerateLayer2(); break;
                case "3": GenerateWebServer(); break;
                case "0": return;
            }
        }

        public static void LoadConfig()
        {
            string configStr = File.ReadAllText("conf/ca.json");
            config = JsonConvert.DeserializeObject<CA_Config>(configStr);
        }

        public static void GenerateSelfSign()
        {
            Console.Clear();
            Console.WriteLine("Generate Self Signed Certificate");
            Console.WriteLine("-----------------------------------------");
            Console.WriteLine("Please Input Your Name in X509 Format:");

            string name = Console.ReadLine();

            if (string.IsNullOrEmpty(name))
            {
                name = config.DefaultSelfSignCAName;
            }

            
            var keyr = new RSACryptoServiceProvider(config.KeySize);
            var key = DotNetUtilities.GetRsaKeyPair(keyr);

            CA_Helper.GenerateSelfSignCert(config, name, key);

            Console.WriteLine("Cert is generated, press any key to exit");
            Console.ReadKey();

            

        }

        public static void GenerateLayer2()
        {
            Console.Clear();
            Console.WriteLine("Generate Layer-2 CA Certificate");
            Console.WriteLine("-----------------------------------------");
            Console.WriteLine("Please Input Your Name in X509 Format:");

            string name = Console.ReadLine();

            if (string.IsNullOrEmpty(name))
            {
                name = config.DefaultCAName;
            }

            Console.WriteLine("Please Input Your CA Name in X509 Format:");

            string caname = Console.ReadLine();

            if (string.IsNullOrEmpty(caname))
            {
                caname = config.DefaultSelfSignCAName;
            }

            
            var keyr = new RSACryptoServiceProvider(config.KeySize);
            var key = DotNetUtilities.GetRsaKeyPair(keyr);

            var capem=File.ReadAllText(config.CertDir+"ca.pem");
            var cakeyr = RSACryptoHelper.PemToRSAKey(capem);
            var cakey = DotNetUtilities.GetRsaKeyPair(cakeyr);

            CA_Helper.GenerateLayer2Cert(config, caname, name, cakey, key);

            Console.WriteLine("Cert is generated, press any key to exit");
            Console.ReadKey();

            
        }

        public static void GenerateWebServer()
        {
            Console.Clear();
            Console.WriteLine("Generate Web Server Certificate");
            Console.WriteLine("-----------------------------------------");
            Console.WriteLine("Please Input Your Name in X509 Format:");

            string name = Console.ReadLine();

            if (string.IsNullOrEmpty(name))
            {
                name = config.DefaultEndUserName;
            }

            Console.WriteLine("Please Input Your CA Name in X509 Format:");

            string caname = Console.ReadLine();

            if (string.IsNullOrEmpty(caname))
            {
                caname = config.DefaultCAName;
            }

            Console.WriteLine("Please Input Your SANs as comma-separated string:");
            string sans = Console.ReadLine();

            
            var keyr = new RSACryptoServiceProvider(config.KeySize);
            var key = DotNetUtilities.GetRsaKeyPair(keyr);

            var capem = File.ReadAllText(config.CertDir + "subca.pem");
            var cakeyr = RSACryptoHelper.PemToRSAKey(capem);
            var cakey = DotNetUtilities.GetRsaKeyPair(cakeyr);

            CA_Helper.GenerateWebServerCert(config, caname, name,sans, cakey, key);

            Console.WriteLine("Cert is generated, press any key to exit");
            Console.ReadKey();

            
        }

    }
}

