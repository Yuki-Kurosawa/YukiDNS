using Newtonsoft.Json;
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
using YukiDNS.CA_CORE;
using YukiDNS.DNS_RFC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using YukiDNS.HTTP_CORE.Kernel;

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
                string[] data = File.ReadAllLines(@"zones\e1.ksyuki.com.flat.zone");

                ZoneArea zone = ZoneParser.ParseArea("e1.ksyuki.com", data);

                List<ZoneData> list = zone.Data;

                foreach (var data1 in list)
                {
                    Console.WriteLine(JsonConvert.SerializeObject(data1));
                }

                Console.ReadLine();
            }
            else if (args[0] == "http")
            {
                HttpServer http = new HttpServer(new[] { "http://127.0.0.1:18888/" }, new Config()
                {
                    defaultPage = new[] { "index.html" },
                    path = "A:\\",
                    prefix = new Prefix[] {
                        new Prefix(){ host="0.0.0.0", port=18888, scheme="http" }
                    },
                    siteId = 1,
                    siteName = "AAA"
                });
                http.StartServer();
                Console.ReadLine();
            }
            else
            {
                CA_Program.Main(args.Skip(1).ToArray());
            }
        }       
    }
}
