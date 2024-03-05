using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using YukiDNS.DNS_RFC;
using System.IO;
using System.Xml.Linq;
using Org.BouncyCastle.Ocsp;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using static Org.BouncyCastle.Math.EC.ECCurve;
using YukiDNS.CA_CORE;
using YukiDNS.COMMON_CORE;

namespace YukiDNS.DNS_CORE
{
    public class DNSService
    {
        public static DNSConfig config;

        public static void Start()
        {
            Thread dns = new Thread(DNS_THREAD_UDP);
            dns.Start();

            Thread dnstcp = new Thread(DNS_THREAD_TCP);
            dnstcp.Start();

            Thread dnstcptls = new Thread(DNS_THREAD_TCP_TLS);
            dnstcptls.Start();
        }

        public static void LoadConfig()
        {
            string configStr = File.ReadAllText("conf/dns.json");
            config = JsonConvert.DeserializeObject<DNSConfig>(configStr);
        }

        static List<ZoneArea> zones = new List<ZoneArea>();
        static List<ZoneConfig> zoneConfigs;

        public static void LoadZoneData()
        {
            string configStr = File.ReadAllText("conf/zones.json");
            zoneConfigs = JsonConvert.DeserializeObject<List<ZoneConfig>>(configStr);
        }

        public static void LoadZoneFiles()
        {
            string basePath = "zones";

            foreach (var zoneConfig in zoneConfigs)
            {
                

                string file = Path.Combine(basePath, zoneConfig.DataFile);
                string flatFile = Path.Combine(basePath, zoneConfig.DataFile+".signed.flat");

                string fn = zoneConfig.Name;

                Console.Write($"Checking Zone {zoneConfig.Name} ... ");

                bool check = DNSTools.CheckZone(zoneConfig.Name, file);

                if(!check)
                {
                    Console.WriteLine("FAILED");
                    Console.WriteLine(ExtToolRunner.Output);
                    break;
                }

                Console.WriteLine("OK");

                Console.WriteLine($@"Check if DNSSEC Status for {zoneConfig.Name} ... {(zoneConfig.DNSSEC ? "ENABLED" : "DISABLED")}");

                bool dnssecOK = false;

                if(zoneConfig.DNSSEC)
                {
                    Console.Write($@"Signing Zone {zoneConfig.Name} ... ");
                    bool sign = DNSTools.SignZone(zoneConfig.Name, zoneConfig.DataFile, zoneConfig.DNSSECKey, zoneConfig.DNSSECSalt);
                    if (!sign)
                    {
                        Console.WriteLine("FAILED");
                        Console.WriteLine(ExtToolRunner.Error);
                        zoneConfig.DNSSEC = false;
                    }
                    else
                    {
                        Console.WriteLine("OK");
                    }

                    if(sign)
                    {
                        Console.Write($@"Flattening Zone {zoneConfig.Name} ... ");
                        bool flat = DNSTools.FlatZone(zoneConfig.Name, zoneConfig.DataFile+".signed");
                        if (!flat)
                        {
                            Console.WriteLine("FAILED");
                            Console.WriteLine(ExtToolRunner.Output);
                            zoneConfig.DNSSEC = false;
                        }
                        else
                        {
                            Console.WriteLine("OK");
                            dnssecOK = true;
                        }
                    }
                }
                else
                {
                    Console.WriteLine($@"Signing Zone {zoneConfig.Name} ... SKIPPED");
                }

                Console.Write($"Loading Zone {zoneConfig.Name} ... ");
                string[] lines = File.ReadAllLines(dnssecOK ? flatFile : file);

                ZoneArea zone = ZoneParser.ParseArea(fn,lines);

                zones.Add(zone);

                Console.WriteLine("Done");
                Console.WriteLine();

            }

            Console.ReadLine();

            Console.WriteLine(JsonConvert.SerializeObject(zones, Formatting.Indented));
        }

        private static void DNS_THREAD_TCP()
        {
            TcpListener tcp = new TcpListener(new IPEndPoint(IPAddress.Any, 53));
            tcp.Start();

            while (true)
            {
                var ret = tcp.AcceptTcpClientAsync().Result;
                var req = new byte[1000];

                var str = ret.GetStream();
                int size = str.Read(req, 0, 1000);

                req = req.Take(size).ToArray();

                req = req.Skip(2).ToArray();


                var dns = ParseDNSRequest(req);

                var dret = Resolve(dns);

                byte[] buf = dret.To();


                str.Write(new[] { (byte)(buf.Length / 256) }, 0, 1);
                str.Write(new[] { (byte)(buf.Length % 256) }, 0, 1);
                str.Write(buf, 0, buf.Length);
                str.Flush();
                str.Close();
                ret.Close();
            }
        }

        private static void DNS_THREAD_TCP_TLS()
        {
            TcpListener tcp = new TcpListener(new IPEndPoint(IPAddress.Any, 853));
            tcp.Start();

            while (true)
            {
                var ret = tcp.AcceptTcpClientAsync().Result;
                var req = new byte[1000];

                var str = new SslStream(ret.GetStream());

                X509Certificate x509 = new X509Certificate("D:\\Github\\YukiDNS\\bin\\Debug\\net6.0\\certs\\ca.pfx", "123456");

                str.AuthenticateAsServer(x509);

                int size = str.Read(req, 0, 1000);

                req = req.Take(size).ToArray();

                req = req.Skip(2).ToArray();


                var dns = ParseDNSRequest(req);

                var dret = Resolve(dns);

                byte[] buf = dret.To();


                str.Write(new[] { (byte)(buf.Length / 256) }, 0, 1);
                str.Write(new[] { (byte)(buf.Length % 256) }, 0, 1);
                str.Write(buf, 0, buf.Length);
                str.Flush();
                str.Close();
                ret.Close();
            }
        }

        private static void DNS_THREAD_UDP()
        {
            UdpClient udp = new UdpClient(new IPEndPoint(IPAddress.Any, 53));

            while (true)
            {
                var ret = udp.ReceiveAsync().Result;
                var req = ret.Buffer;

                var dns = ParseDNSRequest(req);

                var dret = Resolve(dns);

                byte[] buf = dret.To();
                udp.Send(buf, buf.Length, ret.RemoteEndPoint);
            }
        }

        public static DNSRequest Resolve(DNSRequest dns)
        {
            DNSRequest dret = dns.Copy();
            dret.IsResponse = true;
            dret.Addtional = 0;
            //dret.Authed=true;
            dret.IsAuthority = true;
            dret.Z = false;

            List<string> nsec3Names= new List<string>();

            ZoneArea selected = null;
            string Name = "";

            {
                byte[] RR = dns.RRQueries[0].byteData;
                int i = 0;
                for (; i < RR.Length; i++)
                {
                    if (RR[i] == 0) { break; }
                    Name += (char)RR[i];
                }
            }
            Name = Name.FromDNSName().ToLower();

            string zoneName = Name + ".";

            while (selected == null && !string.IsNullOrEmpty(zoneName))
            {
                var zone = zones.Where(k => k.Name == zoneName.TrimEnd('.')).ToList();

                if (dns.RRQueries[0].Type==QTYPES.DS)
                {
                    zone = zones.Where(k => k.Name == zoneName.Substring(zoneName.IndexOf('.') + 1, zoneName.Length - zoneName.IndexOf('.') - 1).TrimEnd('.')).ToList();
                }

                if (zone.Count > 0)
                {
                    selected = zone[0];
                }
                else
                {
                    int len = zoneName.Length - zoneName.IndexOf(".") - 1;
                    zoneName = zoneName.Substring(zoneName.IndexOf(".") + 1, len);
                }
            }

            bool ednsVerCheckOK = true;
            bool dnssecCheckOK = true;

            if (config.EDNS || config.DNSSEC)
            {
                if (dns.Addtional > 0)
                {
                    var opt = dns.RRAdditional[0];

                    if (opt.OPTData.VERSION != 0)
                    {
                        ednsVerCheckOK = false;

                        dret.Addtional = 1;
                        opt.OPTData.RCODE = 1;
                        opt.OPTData.VERSION = 0;
                        opt.OPTData.DO = false;
                        uint TTL = opt.OPTData.RCODE * 0x1000000u + opt.OPTData.VERSION * 0x10000u + (opt.OPTData.DO ? 0x8000u : 0x0u) + opt.OPTData.Z;
                        dret.RRAdditional = new[] {
                            RRData.BuildResponse_OPT(dret.RRAdditional[0].byteData,TTL)
                        };

                        dret.Answer = 0;
                        dret.RRAnswer = new RRData[0];

                        return dret;

                    }

                    dret.Addtional = 1;
                    if (!config.DNSSEC)
                    {
                        dnssecCheckOK = false;
                        opt.OPTData.DO = false;
                    }
                    else if (opt.OPTData.DO == false)
                    {
                        dnssecCheckOK = false;
                    }
                    else
                    {
                        opt.OPTData.DO = true;
                    }
                    uint TTL1 = opt.OPTData.RCODE * 0x10000u + opt.OPTData.VERSION * 0x100u + (opt.OPTData.DO ? 0x8000u : 0x0u) + opt.OPTData.Z;
                    dret.RRAdditional = new[] {
                        RRData.BuildResponse_OPT(dret.RRAdditional[0].byteData,TTL1)
                    };
                }
                else
                {
                    dnssecCheckOK = false;
                }
            }

            if (selected == null)
            {
                dret.ReplyCode = (ushort)ReplyCode.REFUSED;
                dret.Answer = 0;

                return dret;
            }

            bool exact = selected.Name == Name.TrimEnd('.');
            bool any = false;

            string sn = "@";

            if (selected.Name != Name.TrimEnd('.'))
            {
                sn = Name.TrimEnd('.').Substring(0, Name.Length - selected.Name.Length - 1);
            }

            string[] qs = selected.Name == Name.TrimEnd('.') ? new[] { "@" } : new[] { sn, "*" };

            if (dret.RRQueries[0].Type == QTYPES.NS || dret.RRQueries[0].Type == QTYPES.SOA)
            {
                exact = true;
            }

            if (!exact && new[] { QTYPES.A, QTYPES.AAAA, QTYPES.CNAME }.Contains(dret.RRQueries[0].Type))
            {
                string s = sn;
                var exactrr = selected.Data.Where(data => (data.Type == QTYPES.A || data.Type == QTYPES.AAAA || data.Type == QTYPES.CNAME) && data.Name == s).ToList();

                if (exactrr.Count > 0)
                {
                    qs = new[] { sn };
                }
            }
            else if (!exact && new[] { QTYPES.NS, QTYPES.CAA, QTYPES.MX, QTYPES.NS, QTYPES.DS, QTYPES.DNSKEY }.Contains(dret.RRQueries[0].Type))
            {
                string s = sn;
                qs = new[] { sn };
            }


            foreach (string s in qs)
            {
                if (s == "*")
                {
                    any = true;
                    var pl = selected.Data.Where(data => data.Name == s).ToList();

                    //if (pl.Any()) break;
                }

                List<ZoneData> zds = new List<ZoneData>();

                if (exact)
                {
                    zds = selected.Data.Where(data => data.Type == dret.RRQueries[0].Type && data.Name == "@").ToList();
                }
                else if (!any && (dret.RRQueries[0].Type == QTYPES.A || dret.RRQueries[0].Type == QTYPES.AAAA))
                {
                    zds = selected.Data.Where(data => (data.Type == dret.RRQueries[0].Type || data.Type == QTYPES.CNAME) && data.Name == s).ToList();
                }
                else if (any && (dret.RRQueries[0].Type == QTYPES.A || dret.RRQueries[0].Type == QTYPES.AAAA))
                {
                    zds = selected.Data.Where(data => (data.Type == dret.RRQueries[0].Type || data.Type == QTYPES.CNAME) && data.Name == "*").ToList();
                }
                else if (!any)
                {
                    zds = selected.Data.Where(data => data.Type == dret.RRQueries[0].Type && data.Name == s).ToList();
                }
                else
                {
                    zds = selected.Data.Where(data => data.Type == dret.RRQueries[0].Type && data.Name == "*").ToList();
                }

                if (zds.Any())
                {
                    if (!nsec3Names.Contains(zds[0].NSEC3Name))
                    {
                        nsec3Names.Add(zds[0].NSEC3Name);
                    }

                    try
                    {

                        List<RRData> answers = null;

                        if (zds.Where(q => q.Type == QTYPES.CNAME && dret.RRQueries[0].Type != QTYPES.CNAME).Any())
                        {
                            var nq = dret.RRQueries[0].ChangeQueryType(QTYPES.CNAME, s.Replace("@", "") + "." + selected.Name.TrimStart('.'));
                            answers = BuildResponse(nq, zds, dnssecCheckOK);
                            var cname = zds[0].Data[0].ToString();
                            var dnsq = new DNSRequest();
                            dnsq.RRQueries = new RRQuery[1];
                            dnsq.Query = 1;
                            dnsq.RRQueries[0] = dret.RRQueries[0].ChangeName(cname);
                            answers.AddRange(Resolve(dnsq).RRAnswer ?? new RRData[0]);
                        }
                        else
                        {
                            answers = BuildResponse(dret.RRQueries[0], zds, dnssecCheckOK);
                        }
                        if (answers.Any())
                        {
                            dret.Answer = (ushort)answers.Count;
                            dret.RRAnswer = answers.ToArray();
                        }
                    }
                    catch
                    {
                        dret.ReplyCode = (ushort)ReplyCode.NOTIMP;
                    }
                    break;
                }
            }

            string kc = exact ? Name.TrimEnd('.') : Name.TrimEnd('.').Substring(0, Name.Length - selected.Name.Length - 1);

            if (!exact)
            {
                int allCount = selected.Data.Where(data => data.Type != QTYPES.NS && data.Type != QTYPES.SOA && data.Name == kc).ToList().Count;
                if (allCount == 0)
                {
                    allCount = selected.Data.Where(data => data.Type != QTYPES.NS && data.Type != QTYPES.SOA && data.Name == "*").ToList().Count;
                }

                if (allCount == 0 && dret.ReplyCode == (ushort)ReplyCode.NOERROR)
                {
                    dret.ReplyCode = (ushort)ReplyCode.NXDOMAIN;
                }
            }

            //ADD SOA RR and NSEC and NSEC3 for All Records
            {
                var zsoas = selected.Data.Where(data => data.Type == QTYPES.SOA && data.Name == "@").ToList();

                var nq = dret.RRQueries[0].ChangeQueryType(QTYPES.SOA, selected.Name);

                List<RRData> soas = BuildResponse(nq, zsoas, dnssecCheckOK);

                if (ednsVerCheckOK && (config.EDNS || config.DNSSEC))
                {
                    if (config.DNSSEC)
                    {

                        if (dret.ReplyCode != (ushort)ReplyCode.NXDOMAIN)
                        {

                            List<ZoneData> zds = null;

                            if (!any)
                            {
                                zds = selected.Data.Where(data => data.Type == QTYPES.NSEC && data.Name == qs[0]).ToList();
                            }
                            else
                            {
                                zds = selected.Data.Where(data => data.Type == QTYPES.NSEC && data.Name == "*").ToList();
                            }

                            var sq = dret.RRQueries[0].ChangeQueryType(QTYPES.NSEC, selected.Name);
                            soas.AddRange(BuildResponse(sq, zds, dnssecCheckOK));

                        }

                        if (dret.ReplyCode != (ushort)ReplyCode.NXDOMAIN)
                        {

                            List<ZoneData> zds = null;

                            var dnsName = selected.Name.ToDNSName();

                            List<byte> dn = new List<byte>();
                            for (int i = 0; i < dnsName.Length; i++)
                            {
                                dn.Add((byte)dnsName[i]);
                            }

                            if (nsec3Names.Any())
                            {
                                foreach (var r in nsec3Names)
                                {
                                    zds = selected.Data.Where(data => data.Type == QTYPES.NSEC3 && data.Name == r.ToLower()).ToList();

                                    var sq = dret.RRQueries[0].ChangeQueryType(QTYPES.NSEC3, r + "." + selected.Name);
                                    soas.AddRange(BuildResponse(sq, zds, dnssecCheckOK));
                                }
                            }
                            else
                            {
                                var nr = selected.Data.Where(data => data.Type == QTYPES.NSEC3).ToList();

                                foreach (var n in nr)
                                {
                                    string r = n.Name;
                                    zds = selected.Data.Where(data => data.Type == QTYPES.NSEC3 && data.Name == r.ToLower()).ToList();

                                    var sq = dret.RRQueries[0].ChangeQueryType(QTYPES.NSEC3, r + "." + selected.Name);
                                    soas.AddRange(BuildResponse(sq, zds, dnssecCheckOK));
                                }
                            }

                            foreach (var r in zsoas)
                            {
                                if (!nsec3Names.Contains(r.NSEC3Name))
                                {
                                    zds = selected.Data.Where(data => data.Type == QTYPES.NSEC3 && data.Name == r.NSEC3Name).ToList();
                                    var sq = dret.RRQueries[0].ChangeQueryType(QTYPES.NSEC3, r.NSEC3Name + "." + selected.Name);
                                    soas.AddRange(BuildResponse(sq, zds, dnssecCheckOK));
                                }
                            }

                        }
                    }

                    if (soas.Any())
                    {
                        dret.Authority = (ushort)soas.Count;
                        dret.RRAuthority = soas.ToArray();
                    }
                }
            }
            return dret;
        }

        private static List<RRData> BuildResponse(RRQuery query, List<ZoneData> zds,bool dnssecCheckOK)
        {
            List<RRData> answers = new List<RRData>();
            if (query.Type == QTYPES.A)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_A(query.byteData, zds[i-1].TTL, 4, zds[i - 1].Data[0].ToString());
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.AAAA)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_AAAA(query.byteData, zds[i-1].TTL, 16, zds[i - 1].Data[0].ToString());
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.PTR)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString().ToDNSName();
                    var a = RRData.BuildResponse_PTR(query.byteData, zds[i-1].TTL, (ushort)ptr.Length, ptr);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.CNAME)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString().ToDNSName();
                    var a = RRData.BuildResponse_CNAME(query.byteData, zds[i-1].TTL, (ushort)ptr.Length, ptr);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.NS)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString().ToDNSName();
                    var a = RRData.BuildResponse_NS(query.byteData, zds[i-1].TTL, (ushort)ptr.Length, ptr);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.MX)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[1].ToString().ToDNSName();
                    var a = RRData.BuildResponse_MX(query.byteData, zds[i-1].TTL, (ushort)(ptr.Length + 2), (ushort)zds[i - 1].Data[0], ptr);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.TXT)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString();
                    var a = RRData.BuildResponse_TXT(query.byteData, zds[i-1].TTL, (ushort)(ptr.Length + 1), (ushort)ptr.Length, ptr);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {

                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.SPF)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString();
                    var a = RRData.BuildResponse_SPF(query.byteData, zds[i-1].TTL, (ushort)(ptr.Length + 1), (ushort)ptr.Length, ptr);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.SOA)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string zone = zds[i - 1].Data[0].ToString().ToDNSName();
                    string mbox = zds[i - 1].Data[1].ToString().ToDNSName();
                    var a = RRData.BuildResponse_SOA(query.byteData, zds[i-1].TTL, (ushort)(zone.Length + mbox.Length + 20),
                        zone, mbox, (uint)zds[i - 1].Data[2], (uint)zds[i - 1].Data[3], (uint)zds[i - 1].Data[4], (uint)zds[i - 1].Data[5], (uint)zds[i - 1].Data[6]);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.SRV)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string zone = zds[i - 1].Data[3].ToString().ToDNSName();
                    var a = RRData.BuildResponse_SRV(query.byteData, zds[i-1].TTL, (ushort)(zone.Length + 6),
                       (ushort)zds[i - 1].Data[0], (ushort)zds[i - 1].Data[1], (ushort)zds[i - 1].Data[2], zone);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.CAA)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string zone = zds[i - 1].Data[2].ToString();
                    string tag = zds[i - 1].Data[1].ToString();
                    var a = RRData.BuildResponse_CAA(query.byteData, zds[i-1].TTL, (ushort)(zone.Length + tag.Length + 2),
                        (ushort)zds[i - 1].Data[0], (ushort)tag.Length, tag, zone);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }

            }
            else if (query.Type == QTYPES.DNSKEY)
            {
                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_DNSKEY(query.byteData, zds[i-1].TTL, zds[i - 1].Data);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }
            }
            else if (query.Type == QTYPES.DS)
            {
                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_DS(query.byteData, zds[i-1].TTL, zds[i - 1].Data);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }
            }
            else if (query.Type == QTYPES.NSEC)
            {
                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_NSEC(query.byteData, zds[i - 1].TTL, zds[i - 1].Data);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }
            }
            else if (query.Type == QTYPES.NSEC3PARAM)
            {
                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_NSEC3PARAM(query.byteData, zds[i - 1].TTL, zds[i - 1].Data);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }
            }
            else if (query.Type == QTYPES.NSEC3)
            {
                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_NSEC3(query.byteData, zds[i - 1].TTL, zds[i - 1].Data);
                    answers.Add(a);

                    if (config.DNSSEC && dnssecCheckOK)
                    {
                        if (zds[i - 1].RRSIG != null)
                        {
                            var sig = zds[i - 1].RRSIG;
                            var sigq = query.ChangeQueryType(QTYPES.RRSIG, zds[i - 1].Name.Replace("@", "") + "." + zds[i - 1].ZoneName.TrimStart('.'));
                            var b = RRData.BuildResponse_RRSIG(sigq.byteData, sig.TTL, sig.Data);
                            answers.Add(b);
                        }
                    }
                }
            }
            else
            {
                throw new Exception("NOTIMP");
            }

            return answers;
        }

        public static DNSRequest ParseDNSRequest(byte[] req)
        {
            DNSRequest dns = DNSRequest.From(req);

            string Name = "";

            {
                byte[] RR = dns.RRQueries[0].byteData;
                int i = 0;
                for (; i < RR.Length; i++)
                {
                    if (RR[i] == 0) { break; }
                    Name += (char)RR[i];
                }
            }
            Name = Name.FromDNSName();

            //Console.WriteLine(dns.TransactionID.ToString() + " " + (dns.IsResponse ? "RESP" : "REQ") + " " + dns.OpCode.ToString() +
            //    " " + dns.Query.ToString() + " " + dns.Answer.ToString() + " " + dns.Authority.ToString() + " " + dns.Addtional.ToString() +
            //    "\r\n" + Name + " " + dns.RRQueries[0].Type + " " + dns.RRQueries[0].Class + "\r\n");
            //Console.WriteLine("===================\r\n" + JsonConvert.SerializeObject(dns) + "\r\n===================\r\n");
            /*txtLog.SelectionStart = txtLog.TextLength;
            txtLog.ScrollToCaret();*/
            return dns;
        }

    }
}
