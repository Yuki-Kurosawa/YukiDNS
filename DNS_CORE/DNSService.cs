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

namespace YukiDNS.DNS_CORE
{
    public class DNSService
    {
        public static void Start()
        {
            LoadZoneFiles();

            Thread dns = new Thread(DNS_THREAD_UDP);
            dns.Start();

            Thread dnstcp = new Thread(DNS_THREAD_TCP);
            dnstcp.Start();
        }

        static List<ZoneArea> zones = new List<ZoneArea>();

        public static void LoadZoneFiles()
        {
            string basePath = "zones";
            string[] fs=Directory.GetFiles(basePath);

            foreach (string file in fs)
            {
                string fn=new FileInfo(file).Name.Replace(".zone","").Replace("_",".");
                ZoneArea zone = new ZoneArea(fn);
                string[] lines=File.ReadAllLines(file);

                foreach (string line in lines)
                {
                    try
                    {
                        ZoneData data = ZoneParser.ParseLine(line);
                        zone.Data.Add(data);
                    }
                    catch
                    {
                    }
                }
                zones.Add(zone);
            }
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

        private static DNSRequest Resolve(DNSRequest dns)
        {
            DNSRequest dret = dns.Copy();
            dret.IsResponse = true;
            dret.Addtional = 0;
            //dret.Authed=true;
            dret.IsAuthority = true;
            dret.Z = false;



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
            Name = Name.FromDNSName();

            string zoneName = Name+".";

            while(selected == null && !string.IsNullOrEmpty(zoneName))
            {
                var zone = zones.Where(k => k.Name == zoneName.TrimEnd('.')).ToList();
                if(zone.Count>0)
                {
                    selected = zone[0];
                }
                else
                {
                    int len = zoneName.Length - zoneName.IndexOf(".") - 1;
                    zoneName = zoneName.Substring(zoneName.IndexOf(".") + 1, len);
                }
            }

            if (dns.Addtional > 0)
            {
                var opt = dns.RRAdditional[0];

                if (opt.OPTData.VERSION != 0)
                {
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
                opt.OPTData.DO = false;
                uint TTL1 = opt.OPTData.RCODE * 0x10000u + opt.OPTData.VERSION * 0x100u + (opt.OPTData.DO ? 0x8000u : 0x0u) + opt.OPTData.Z;
                dret.RRAdditional = new[] {
                    RRData.BuildResponse_OPT(dret.RRAdditional[0].byteData,TTL1)
                };
            }

            if(selected==null)
            {
                dret.ReplyCode = (ushort)ReplyCode.NXDOMAIN;
                dret.Answer = 0;
                return dret;
            }

            bool exact = selected.Name == Name.TrimEnd('.');
            bool any = false;
            string[] qs = selected.Name == Name.TrimEnd('.') ? new[] { "@" } : new[] { Name.TrimEnd('.').Substring(0, Name.Length - selected.Name.Length - 1), "*" };

            foreach(string s in qs)
            {
                if (s == "*") any = true;
                List<ZoneData> zds = new List<ZoneData>();

                if (exact)
                {
                    zds = selected.Data.Where(data => data.Type == dret.RRQueries[0].Type && data.Name == "@").ToList();
                }
                else if(!any)
                {
                    zds = selected.Data.Where(data => data.Type == dret.RRQueries[0].Type && data.Name == s).ToList();
                }
                else
                {
                    zds = selected.Data.Where(data => data.Type == dret.RRQueries[0].Type && data.Name == "*").ToList();
                }

                if (zds.Any())
                {
                    try
                    {
                        List<RRData> answers = BuildResponse(dret.RRQueries[0], zds);
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

            if(dret.Answer == 0 && dret.ReplyCode==(ushort)ReplyCode.NOERROR) {
                dret.ReplyCode = (ushort)ReplyCode.NXDOMAIN;
            }
            

            return dret;
        }

        private static List<RRData> BuildResponse(RRQuery query, List<ZoneData> zds)
        {
            List<RRData> answers = new List<RRData>();
            if (query.Type == QTYPES.A)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_A(query.byteData, 1, 4, zds[i-1].Data[0].ToString());
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.AAAA)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    var a = RRData.BuildResponse_AAAA(query.byteData, 1, 16, zds[i - 1].Data[0].ToString());
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.PTR)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString().ToDNSName();
                    var a = RRData.BuildResponse_PTR(query.byteData, 1, (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.CNAME)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString().ToDNSName();
                    var a = RRData.BuildResponse_CNAME(query.byteData, 1, (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.NS)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString().ToDNSName();
                    var a = RRData.BuildResponse_NS(query.byteData, 1, (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.MX)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = $@"mx{i}.test.com".ToDNSName();
                    var a = RRData.BuildResponse_MX(query.byteData, 1, (ushort)(ptr.Length + 2), (ushort)i, ptr);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.TXT)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString();
                    var a = RRData.BuildResponse_TXT(query.byteData, 1, (ushort)(ptr.Length + 1), (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.SPF)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string ptr = zds[i - 1].Data[0].ToString();
                    var a = RRData.BuildResponse_SPF(query.byteData, 1, (ushort)(ptr.Length + 1), (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.SOA)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string zone = $@"test.com".ToDNSName();
                    string mbox = $@"admin.test.com".ToDNSName();
                    var a = RRData.BuildResponse_SOA(query.byteData, 1, (ushort)(zone.Length + mbox.Length + 20),
                        zone, mbox, 1, 2, 3, 4, 5);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.SRV)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string zone = $@"test.com".ToDNSName();
                    var a = RRData.BuildResponse_SRV(query.byteData, 1, (ushort)(zone.Length + 6),
                        1, 2, 53, zone);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.CAA)
            {

                for (var i = 1; i <= zds.Count; i++)
                {
                    string zone = $@"test.com";
                    string tag = "issue";
                    var a = RRData.BuildResponse_CAA(query.byteData, 1, (ushort)(zone.Length + tag.Length + 2),
                        0, (ushort)tag.Length, tag, zone);
                    answers.Add(a);
                }

            }
            else if (query.Type == QTYPES.DNSKEY)
            {
                
            }
            else
            {
                throw new Exception("NOTIMP");
            }

            return answers;
        }

        private static DNSRequest ParseDNSRequest(byte[] req)
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

            Console.WriteLine(dns.TransactionID.ToString() + " " + (dns.IsResponse ? "RESP" : "REQ") + " " + dns.OpCode.ToString() +
                " " + dns.Query.ToString() + " " + dns.Answer.ToString() + " " + dns.Authority.ToString() + " " + dns.Addtional.ToString() +
                "\r\n" + Name + " " + dns.RRQueries[0].Type + " " + dns.RRQueries[0].Class + "\r\n");
            Console.WriteLine( "===================\r\n"+ JsonConvert.SerializeObject(dns)+"\r\n===================\r\n");
            /*txtLog.SelectionStart = txtLog.TextLength;
            txtLog.ScrollToCaret();*/
            return dns;
        }

    }
}
