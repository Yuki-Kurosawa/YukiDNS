using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace YukiDNS.DNS_RFC
{
    public class DNSRequest
    {
        public ushort TransactionID { get; set; }//16

        #region Flag

        public bool IsResponse { get; set; }//1

        public DNSOpType OpCode { get; set; }//4

        public bool IsAuthority { get; set; }//1

        public bool Truncated { get; set; }//1

        public bool RecursionDesired { get; set; }//1

        public bool RecursionAccepted { get; set; }//1

        public bool Z { get; set; }//1

        public bool Authed { get; set; }//1

        public bool AuthData { get; set; }//1

        public ushort ReplyCode { get; set; } //4

        #endregion

        #region RRs

        public ushort Query { get; set; }

        public ushort Answer { get; set; }

        public ushort Authority { get; set; }

        public ushort Addtional { get; set; }

        #endregion

        #region RRs Data

        public RRQuery[] RRQueries { get; set; }

        public RRAnswer[] RRAnswer { get; set; }

        public RRAuthority[] RRAuthority { get; set; }

        public RRAdditional[] RRAdditional { get; set; }

        #endregion

        public static DNSRequest From(byte[] req)
        {
            DNSRequest ret = new DNSRequest();
            ret.TransactionID = (ushort)(req[0] * 256 + req[1]);

            ushort flag = (ushort)(req[2] * 256 + req[3]);
            ret.IsResponse = (flag & 32768) == 32768;

            DNSOpType type = (DNSOpType)((flag / 2048) & 15);
            ret.OpCode = type;

            #region Flags

            ret.IsAuthority = (flag & 1024) == 1024;
            ret.Truncated = (flag & 512) == 512;
            ret.RecursionDesired = (flag & 256) == 256;
            ret.RecursionAccepted = (flag & 128) == 128;
            ret.Z = (flag & 64) == 64;
            ret.Authed = (flag & 32) == 32;
            ret.AuthData = (flag & 16) == 16;
            ret.ReplyCode = (ushort)(flag & 15);

            #endregion

            #region RR Count

            byte[] data = new List<byte>(req.Skip(4)).ToArray();

            ret.Query = (ushort)(data[0] * 256 + data[1]);
            data = new List<byte>(data.Skip(2)).ToArray();

            ret.Answer = (ushort)(data[0] * 256 + data[1]);
            data = new List<byte>(data.Skip(2)).ToArray();

            ret.Authority = (ushort)(data[0] * 256 + data[1]);
            data = new List<byte>(data.Skip(2)).ToArray();

            ret.Addtional = (ushort)(data[0] * 256 + data[1]);
            data = new List<byte>(data.Skip(2)).ToArray();

            #endregion

            //DO RR DATAS

            ParseRR(ref ret, ref data);

            return ret;
        }

        private static void ParseRR(ref DNSRequest ret, ref byte[] data)
        {
            {
                List<RRQuery> rs = new List<RRQuery>();
                for (int i = 0; i < ret.Query; i++)
                {
                    RRData rr = new RRData(data);
                    rs.Add(new RRQuery(rr.byteData));
                    data = new List<byte>(data.Skip(rr.byteData.Length)).ToArray();
                }
                ret.RRQueries = rs.ToArray();
            }

            /*{
                List<RRAuthority> rs = new List<RRAuthority>();
                for (int i = 0; i < ret.Authority; i++)
                {
                    RRData rr = new RRData(data);
                    rs.Add(new RRAuthority(rr.byteData));
                    data = new List<byte>(data.Skip(rr.byteData.Length)).ToArray();
                }
                ret.RRAuthority = rs.ToArray();
            }*/
        }

        public byte[] To()
        {
            List<byte> ret = new List<byte>();
            ret.Add((byte)(TransactionID / 256));
            ret.Add((byte)(TransactionID % 256));


            //FLAGS
            ushort Flags = 0;
            Flags |= IsResponse ? 32768 : 0;
            Flags |= (ushort)((ushort)OpCode * 2048);
            Flags |= IsAuthority ? 1024 : 0;
            Flags |= Truncated ? 512 : 0;
            Flags |= RecursionDesired ? 256 : 0;
            Flags |= RecursionAccepted ? 128 : 0;
            Flags |= Z ? 64 : 0;
            Flags |= Authed ? 32 : 0;
            Flags |= AuthData ? 16 : 0;
            Flags |= ReplyCode;


            ret.Add((byte)(Flags / 256));
            ret.Add((byte)(Flags % 256));

            //RR Count
            ret.Add((byte)(Query / 256));
            ret.Add((byte)(Query % 256));
            ret.Add((byte)(Answer / 256));
            ret.Add((byte)(Answer % 256));
            ret.Add((byte)(Authority / 256));
            ret.Add((byte)(Authority % 256));
            ret.Add((byte)(Addtional / 256));
            ret.Add((byte)(Addtional % 256));

            //RR Datas
            for (var i = 0; i < Query; i++)
            {
                ret.AddRange(RRQueries[i].byteData);
            }

            for (var i = 0; i < Answer; i++)
            {
                ret.AddRange(RRAnswer[i].byteData);
            }

            for (var i = 0; i < Authority; i++)
            {
                ret.AddRange(RRAuthority[i].byteData);
            }

            for (var i = 0; i < Addtional; i++)
            {
                ret.AddRange(RRAdditional[i].byteData);
            }

            return ret.ToArray();
        }

        public DNSRequest Copy()
        {
            DNSRequest obj = new DNSRequest();
            foreach (var p in obj.GetType().GetProperties())
            {
                p.SetValue(obj, p.GetValue(this));
            }
            return obj;
        }

    }

    public class RRData
    {
        public byte[] byteData { get; private set; }

        public string Name { get; private set; }

        public QTYPES Type { get; private set; }

        public RRClass Class { get; private set; }

        public RRData(byte[] RR)
        {

            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                Name += (char)RR[i];
            }

            Name = Name.FromDNSName();

            Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            byte[] data = RR.Take(i + 5).ToArray();
            byteData = data;
        }
    }

    public class RRQuery
    {
        public byte[] byteData { get; private set; }

        public string Name { get; private set; }

        public QTYPES Type { get; private set; }

        public RRClass Class { get; private set; }

        public RRQuery(byte[] RR)
        {
            byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                Name += (char)RR[i];
            }

            Name = Name.FromDNSName();

            Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);
        }
    }

    public class RRAnswer
    {
        public byte[] byteData { get; private set; }

        public string Name { get; private set; }

        public QTYPES Type { get; private set; }

        public RRClass Class { get; private set; }

        public ushort TTL { get; private set; }

        public ushort RDLength { get; private set; }

        public byte[] RDData { get; private set; }

        public static RRAnswer BuildResponse_A(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            //RD Data
            ret.byteData = ret.byteData.Append(byte.Parse(rdData.Split('.')[0])).ToArray();
            ret.byteData = ret.byteData.Append(byte.Parse(rdData.Split('.')[1])).ToArray();
            ret.byteData = ret.byteData.Append(byte.Parse(rdData.Split('.')[2])).ToArray();
            ret.byteData = ret.byteData.Append(byte.Parse(rdData.Split('.')[3])).ToArray();

            return ret;
        }

        public static RRAnswer BuildResponse_AAAA(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            //RD Data
            byte[] rd = IPAddress.Parse(rdData).GetAddressBytes();
            for (var j = 0; j < 16; j++)
            {
                ret.byteData = ret.byteData.Append(rd[j]).ToArray();
            }

            return ret;
        }

        public static RRAnswer BuildResponse_PTR(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            //RD Data
            byte[] rd = Encoding.ASCII.GetBytes(rdData);
            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rd[j]).ToArray();
            }

            return ret;
        }

        public static RRAnswer BuildResponse_CNAME(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            //RD Data
            byte[] rd = Encoding.ASCII.GetBytes(rdData);
            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rd[j]).ToArray();
            }

            return ret;
        }

        public static RRAnswer BuildResponse_NS(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            //RD Data
            byte[] rd = Encoding.ASCII.GetBytes(rdData);
            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rd[j]).ToArray();
            }

            return ret;
        }

        public static RRAnswer BuildResponse_MX(byte[] RR, uint TTL, ushort rdLen,ushort rdPriority, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(rdPriority/256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdPriority%256)).ToArray();

            //RD Data
            byte[] rd = Encoding.ASCII.GetBytes(rdData);
            for (var j = 0; j < rdLen - 2; j++)
            {
                ret.byteData = ret.byteData.Append(rd[j]).ToArray();
            }

            return ret;
        }

        public static RRAnswer BuildResponse_TXT(byte[] RR, uint TTL, ushort rdLen,ushort dataLen, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            
            ret.byteData = ret.byteData.Append((byte)(dataLen % 256)).ToArray();

            //RD Data
            byte[] rd = Encoding.ASCII.GetBytes(rdData);
            for (var j = 0; j < rdLen - 1; j++)
            {
                ret.byteData = ret.byteData.Append(rd[j]).ToArray();
            }

            return ret;
        }

        public static RRAnswer BuildResponse_SPF(byte[] RR, uint TTL, ushort rdLen, ushort dataLen, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();


            ret.byteData = ret.byteData.Append((byte)(dataLen % 256)).ToArray();

            //RD Data
            byte[] rd = Encoding.ASCII.GetBytes(rdData);
            for (var j = 0; j < rdLen - 1; j++)
            {
                ret.byteData = ret.byteData.Append(rd[j]).ToArray();
            }

            return ret;
        }

        public static RRAnswer BuildResponse_SOA(byte[] RR, uint TTL, ushort rdLen, string zone,string mbox,uint serial,uint refresh,uint retry,uint expire,uint minimum)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            //RD Data
            {
                byte[] rd = Encoding.ASCII.GetBytes(zone);
                for (var j = 0; j < rd.Length; j++)
                {
                    ret.byteData = ret.byteData.Append(rd[j]).ToArray();
                }
            }

            {
                byte[] rd = Encoding.ASCII.GetBytes(mbox);
                for (var j = 0; j < rd.Length; j++)
                {
                    ret.byteData = ret.byteData.Append(rd[j]).ToArray();
                }
            }

            
            ret.byteData = ret.byteData.Append((byte)(serial / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(serial % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(serial % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(serial % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(refresh / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(refresh % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(refresh % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(refresh % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(retry / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(retry % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(retry % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(retry % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(expire / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(expire % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(expire % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(expire % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(minimum / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(minimum % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(minimum % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(minimum % 256)).ToArray();

            return ret;
        }

        public static RRAnswer BuildResponse_SRV(byte[] RR, uint TTL, ushort rdLen, ushort rdPriority,ushort rdWeight,ushort rdPort, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(rdPriority / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdPriority % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(rdWeight / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdWeight % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(rdPort / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdPort % 256)).ToArray();

            //RD Data
            byte[] rd = Encoding.ASCII.GetBytes(rdData);
            for (var j = 0; j < rdLen - 6; j++)
            {
                ret.byteData = ret.byteData.Append(rd[j]).ToArray();
            }

            return ret;
        }

        public static RRAnswer BuildResponse_CAA(byte[] RR, uint TTL, ushort rdLen, ushort rdFlag, ushort rdTagLen, string rdTag, string rdData)
        {
            RRAnswer ret = new RRAnswer();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(rdFlag % 256)).ToArray();

            ret.byteData = ret.byteData.Append((byte)(rdTagLen % 256)).ToArray();


            //RD Data
            {
                byte[] rd = Encoding.ASCII.GetBytes(rdTag);
                for (var j = 0; j < rd.Length; j++)
                {
                    ret.byteData = ret.byteData.Append(rd[j]).ToArray();
                }
            }

            {
                byte[] rd = Encoding.ASCII.GetBytes(rdData);
                for (var j = 0; j < rd.Length; j++)
                {
                    ret.byteData = ret.byteData.Append(rd[j]).ToArray();
                }
            }

            return ret;
        }

    }

    public class RRAuthority
    {
        public byte[] byteData { get; private set; }

        public string Name { get; private set; }

        public QTYPES Type { get; private set; }

        public RRClass Class { get; private set; }

        public RRAuthority(byte[] RR)
        {
            byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                Name += (char)RR[i];
            }

            Name = Name.FromDNSName();

            Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);
        }
    }

    public class RRAdditional
    {
        public byte[] byteData { get; private set; }

        public string Name { get; private set; }

        public QTYPES Type { get; private set; }

        public RRClass Class { get; private set; }

        public RRAdditional(byte[] RR)
        {
            byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) break;
                Name += (char)RR[i];
            }

            Name = Name.FromDNSName();

            Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);
        }
    }

    public enum ReplyCode
    {
        NOERROR, FORMERR, SERVFAIL,
        NXDOMAIN, NOTIMP, REFUSED,
        YXDOMAIN, YXRRSET, NXRRSET,
        NOTAUTH, NOTZONE, RESERVED11,
        RESERVED12, RESERVED13, RESERVED14,
        RESERVED15, BADVERS
    }

    public enum DNSOpType
    {
        Standard_Query = 0
    }

    public enum RRClass
    {
        IN = 1,
        CS = 2,
        CH = 3,
        HS = 4
    }

    public enum QTYPES
    {
        NONE = 0,
        ANY = 255,
        A = 1,
        AAAA = 28,
        CAA = 257,
        CNAME = 5,
        MX = 15,
        NS = 2,
        PTR = 12,
        SOA = 6,
        SPF = 99,
        SRV = 33,
        TXT = 16
    }

    public static class DNSName
    {
        public static string ToDNSName(this string name)
        {
            string iname = name;
            if (iname.Last() != '.')
            {
                iname += ".";
            }
            string ret = "", tmp = "";

            int i = 0;
            for(int c = 0; c < iname.Length; c++)
            {
                if (iname[c] != '.')
                {
                    i++;
                    tmp += iname[c];
                }
                else
                {
                    ret += (char)i + tmp;
                    tmp = "";
                    i = 0;
                }
            }

            ret += (char)0;

            return ret;
        }
    
        public static string FromDNSName(this string dname)
        {
            string ret = "", tmp = "";

            int i = 0, id = 0;
            bool dot = true;

            for(int c = 0; c < dname.Length; c++)
            {
                if (dot)
                {
                    i = dname[c];
                    id = 0;
                    dot = false;
                    tmp = "";
                }
                else
                {
                    tmp += dname[c];
                    id++;
                    if (id == i)
                    {
                        ret += tmp + ".";
                        dot = true;
                    }
                }
            }

            return ret.TrimEnd('.');
        }

    }
}