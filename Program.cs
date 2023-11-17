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
                string[] data = File.ReadAllLines(@"test_com.zone");

                foreach (string line in data)
                {
                    try
                    {
                        ZoneData data1=ZoneParser.ParseLine(line);
                        Console.WriteLine(JsonConvert.SerializeObject(data1));
                    }
                    catch(Exception ex)
                    {
                        Console.WriteLine(ex.Message+":"+line.Split(' ')[3]);
                    }
                }

                Console.ReadLine();
            }
            else
            {
                CA_Program.Main(args.Skip(1).ToArray());
            }
        }       
    }
}
