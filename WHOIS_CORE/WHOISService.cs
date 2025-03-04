using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System;
using System.Text;
using Newtonsoft.Json;
using static Org.BouncyCastle.Math.EC.ECCurve;
using YukiDNS.DNS_CORE;
using System.IO;
using System.Collections.Generic;
using System.Reflection;
using System.ComponentModel;

namespace YukiDNS.WHOIS_CORE
{
    public class WHOISService
    {
        public static WHOISConfig config = null;
        public static List<WHOISDBObject> whoisdb = new List<WHOISDBObject>();

        public static void LoadConfig()
        {
            string configStr = File.ReadAllText("conf/whois.json");
            config = JsonConvert.DeserializeObject<WHOISConfig>(configStr);
            whoisdb=new List<WHOISDBObject>();

            if (!Directory.Exists("whoisdb"))
            {
                Directory.CreateDirectory("whoisdb");
            }

            foreach (var file in Directory.GetFiles("whoisdb"))
            {
                var db = JsonConvert.DeserializeObject<WHOISDBObject>(File.ReadAllText(file));
                whoisdb.Add(db);
            }
        }

        public static void Start()
        {
            Thread whois = new Thread(WHOIS_THREAD_TCP);
            whois.Start();
        }

        private static void WHOIS_THREAD_TCP()
        {
            // LISTEN TO WHOIS RFC PORT 43
            TcpListener tcp = new TcpListener(new IPEndPoint(IPAddress.Any, 43));
            tcp.Start();

            while (true)
            {
                var ret = tcp.AcceptTcpClientAsync().Result;
                var req = new byte[1000];

                var str = ret.GetStream();
                int size = str.Read(req, 0, 1000);

                req = req.Take(size).ToArray();


                try
                {
                    // PARSE WHOIS REQUEST To name string
                    var name = ParseWHOISRequest(req);

                    // RESOLVE WHOIS REQUEST
                    var dret = Resolve(name);

                    byte[] buf = Encoding.ASCII.GetBytes(dret);

                    str.Write(buf, 0, buf.Length);
                    str.Flush();
                }
                catch
                {

                }
                str.Close();
                ret.Close();
            }
        }

        private static string Resolve(string name)
        {
            if (string.IsNullOrEmpty(name.Trim()))
            {
                return "no domain name specified.\r\n";
            }
            else if (name.Trim().ToLower().Contains("whois."))
            {
                return ResolveWhoisInnerDomains(name.Trim());
            }
            else
            {
                return ResolveFromWhoisDb(name.Trim());
            }
            
        }

        private static string ResolveFromWhoisDb(string name)
        {
            if(!whoisdb.Any(x => x.DomainName == name))
            {
                return "no match for domain \"" + name.ToUpper() + "\".\r\n";
            }
            else
            {
                return BuildWhoisResponseString(whoisdb.First(x => x.DomainName == name));
            }

        }

        private static string BuildWhoisResponseString(WHOISDBObject value)
        {
            //Build WHOIS Response String from WHOISDBObject Here
            string ret = "";
            ret += BuildWhoisBasicInfo(value);
            ret += BuildWhoisContactInfo(value);
            ret += BuildWhoisNameServerInfo(value);
            ret += "\r\n";
            return ret;
        }

        private static string BuildWhoisNameServerInfo(WHOISDBObject value)
        {
            string ret = "";

            foreach(string ns in value.NameServer)
            {
                ret += $"Name Server: {ns}\r\n";
            }

            return ret;
        }

        private static string BuildWhoisContactInfo(WHOISDBObject value)
        {
            string[] propNames = ["Registrant", "Admin", "Tech", "Billing"];

            string ret = "";

            foreach(string prop in propNames) {
                PropertyInfo propInfo = value.GetType().GetProperty(prop);
                string propDesc = ((DescriptionAttribute)propInfo.GetCustomAttributes(typeof(DescriptionAttribute), false).First()).Description;
                var propValue = propInfo.GetValue(value, null);
                if (propValue != null)
                {
                    ret += BuildWhoisContactInfoDetail(propDesc,(RegistryInfoObject)propValue);
                }
            }
            return ret;
        }

        private static string BuildWhoisContactInfoDetail(string desc,RegistryInfoObject value)
        {
            string ret = "";

            //Build WHOIS Contact Info Detail Here from RegistryInfoObject Properties and Descriptions
            PropertyInfo[] propInfos = value.GetType().GetProperties();

            foreach( PropertyInfo propInfo in propInfos )
            {
                string propDesc = ((DescriptionAttribute)propInfo.GetCustomAttributes(typeof(DescriptionAttribute), false).First()).Description;
                var propValue = propInfo.GetValue(value, null);
                if (propValue != null)
                {
                    ret += $"{string.Format(propDesc, desc)}: {propValue}\r\n";
                }
            }

            return ret;
        }

        private static string BuildWhoisBasicInfo(WHOISDBObject value)
        {
            string[] propNames = ["DomainName", "RegistryDomainID", "RegistrarWHOISServer", "RegistrarURL", "UpdatedDate", "CreationDate", "RegistryExpiryDate", "Registrar", "RegistrarIANAID", "RegistrarAbuseContactEmail", "RegistrarAbuseContactPhone", "DomainStatus"];

            string ret = "";

            foreach (var prop in propNames)
            {
                PropertyInfo propInfo = value.GetType().GetProperty(prop);

                string propDesc = ((DescriptionAttribute)propInfo.GetCustomAttributes(typeof(DescriptionAttribute), false).First()).Description;

                var propValue = propInfo.GetValue(value, null);
                if (propValue != null)
                {
                    if (prop == "DomainStatus")
                    {
                        var dss = (DomainEPPStatus[])propValue;
                        foreach(var ds in dss)
                        {
                            // get description from DomainEPPStatus enum
                            DescriptionAttribute descAttr = (DescriptionAttribute)typeof(DomainEPPStatus).
                                GetField(ds.ToString()).GetCustomAttribute(typeof(DescriptionAttribute));

                            ret+= $"{propDesc}: {ds} ({descAttr.Description})\r\n";
                        }
                    }
                    else
                    {
                        ret += $"{propDesc}: {propValue}\r\n";
                    }
                }
            }

            return ret;
        }

        private static string ResolveWhoisInnerDomains(string name)
        {
            if(config.DontResolveInnerDomains)
            {
                return null;
            }
            switch (name.Replace("whois.",""))
            {
                case "version":
                    return "YukiDNS WHOIS Server v1.0\r\n";
                case "motd":
                    return config.Motd;
                default:
                    return $"no match for domain \"{name}\".\r\n";
            }
        }

        private static string ParseWHOISRequest(byte[] req)
        {
            return Encoding.ASCII.GetString(req);
        }
    }
}
