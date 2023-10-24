using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using YukiDNS.DNS_RFC;

namespace YukiDNS.DNS_CORE
{
    public class DNSService
    {
        public static void Start()
        {
            Thread dns = new Thread(DNS_THREAD_UDP);
            dns.Start();

            Thread dnstcp = new Thread(DNS_THREAD_TCP);
            dnstcp.Start();
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

            if (dret.RRQueries[0].Type == QTYPES.A)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    var a = RRData.BuildResponse_A(dret.RRQueries[0].byteData, 1, 4, "127.0.0." + i.ToString());
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();

            }
            else if (dret.RRQueries[0].Type == QTYPES.AAAA)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    var a = RRData.BuildResponse_AAAA(dret.RRQueries[0].byteData, 1, 16, "::1");
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();

            }
            else if (dret.RRQueries[0].Type == QTYPES.PTR)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string ptr = "ptr.test.com".ToDNSName();
                    var a = RRData.BuildResponse_PTR(dret.RRQueries[0].byteData, 1, (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else if (dret.RRQueries[0].Type == QTYPES.CNAME)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string ptr = "ptr.test.com".ToDNSName();
                    var a = RRData.BuildResponse_CNAME(dret.RRQueries[0].byteData, 1, (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else if (dret.RRQueries[0].Type == QTYPES.NS)
            {
                dret.ReplyCode = 0;
                dret.Answer = 2;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string ptr = $@"ns{i}.test.com".ToDNSName();
                    var a = RRData.BuildResponse_NS(dret.RRQueries[0].byteData, 1, (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else if (dret.RRQueries[0].Type == QTYPES.MX)
            {
                dret.ReplyCode = 0;
                dret.Answer = 2;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string ptr = $@"mx{i}.test.com".ToDNSName();
                    var a = RRData.BuildResponse_MX(dret.RRQueries[0].byteData, 1, (ushort)(ptr.Length + 2), (ushort)i, ptr);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else if (dret.RRQueries[0].Type == QTYPES.TXT)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string ptr = $@"TXT: HELLO WORLD! FROM DNS";
                    var a = RRData.BuildResponse_TXT(dret.RRQueries[0].byteData, 1, (ushort)(ptr.Length + 1), (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else if (dret.RRQueries[0].Type == QTYPES.SPF)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string ptr = $@"SPF: HELLO WORLD! FROM DNS";
                    var a = RRData.BuildResponse_SPF(dret.RRQueries[0].byteData, 1, (ushort)(ptr.Length + 1), (ushort)ptr.Length, ptr);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else if (dret.RRQueries[0].Type == QTYPES.SOA)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string zone = $@"test.com".ToDNSName();
                    string mbox = $@"admin.test.com".ToDNSName();
                    var a = RRData.BuildResponse_SOA(dret.RRQueries[0].byteData, 1, (ushort)(zone.Length + mbox.Length + 20),
                        zone, mbox, 1, 2, 3, 4, 5);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else if (dret.RRQueries[0].Type == QTYPES.SRV)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string zone = $@"test.com".ToDNSName();
                    var a = RRData.BuildResponse_SRV(dret.RRQueries[0].byteData, 1, (ushort)(zone.Length + 6),
                        1, 2, 53, zone);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else if (dret.RRQueries[0].Type == QTYPES.CAA)
            {
                dret.ReplyCode = 0;
                dret.Answer = 1;
                List<RRData> answers = new List<RRData>();

                for (var i = 1; i <= dret.Answer; i++)
                {
                    string zone = $@"test.com";
                    string tag = "issue";
                    var a = RRData.BuildResponse_CAA(dret.RRQueries[0].byteData, 1, (ushort)(zone.Length + tag.Length + 2),
                        0, (ushort)tag.Length, tag, zone);
                    answers.Add(a);
                }

                dret.RRAnswer = answers.ToArray();
            }
            else
            {
                dret.ReplyCode = 4;
            }

            return dret;
        }

        private static DNSRequest ParseDNSRequest(byte[] req)
        {
            DNSRequest dns = DNSRequest.From(req);
            /*txtLog.Text += dns.TransactionID.ToString() + " " + (dns.IsResponse ? "RESP" : "REQ") + " " + dns.OpCode.ToString() +
                " " + dns.Query.ToString() + " " + dns.Answer.ToString() + " " + dns.Authority.ToString() + " " + dns.Addtional.ToString() +
                "\r\n" + dns.RRQueries[0].Name + " " + dns.RRQueries[0].Type + " " + dns.RRQueries[0].Class+"\r\n";
            txtLog.Text += "===================\r\n"+ JsonConvert.SerializeObject(dns)+"\r\n===================\r\n";
            txtLog.SelectionStart = txtLog.TextLength;
            txtLog.ScrollToCaret();*/
            return dns;
        }

    }
}
