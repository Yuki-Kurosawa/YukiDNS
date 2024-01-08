using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using Newtonsoft.Json;
using System.Text.RegularExpressions;
using System.Reflection;

namespace YukiDNS.DNS_RFC
{
    public class RRData
    {
        public byte[] byteData { get; private set; }

        public string Name { get; private set; }

        public QTYPES Type { get; private set; }

        public RRClass Class { get; private set; }

        public uint TTL { get; private set; }

        public RROPTData OPTData { get; private set; }

        public ushort RDLength { get; private set; }

        public byte[] RDData { get; private set; }

        public static RRData BuildResponse_A(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_AAAA(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_PTR(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_CNAME(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_NS(byte[] RR, uint TTL, ushort rdLen, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_MX(byte[] RR, uint TTL, ushort rdLen,ushort rdPriority, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_TXT(byte[] RR, uint TTL, ushort rdLen,ushort dataLen, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_SPF(byte[] RR, uint TTL, ushort rdLen, ushort dataLen, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_SOA(byte[] RR, uint TTL, ushort rdLen, string zone,string mbox,uint serial,uint refresh,uint retry,uint expire,uint minimum)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_SRV(byte[] RR, uint TTL, ushort rdLen, ushort rdPriority,ushort rdWeight,ushort rdPort, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_CAA(byte[] RR, uint TTL, ushort rdLen, ushort rdFlag, ushort rdTagLen, string rdTag, string rdData)
        {
            RRData ret = new RRData();
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

        public static RRData BuildResponse_OPT(byte[] RR,uint TTL)
        {
            RRData ret = new RRData();
            ret.byteData = RR;

            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) { ret.Name = ""; break; }
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);

            //REMOVE OTHER DATAS
            ret.byteData = RR.Take(i + 5).ToArray();

            //TTL
            ret.byteData = ret.byteData.Append((byte)(TTL / 16777216)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 16777216 / 65536)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 65536 / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(TTL % 256)).ToArray();

            //RDLENGTH=
            ret.byteData = ret.byteData.Append((byte)0).ToArray();
            ret.byteData = ret.byteData.Append((byte)0).ToArray();

            return ret;
        }

        public static RRData ParseRequest(byte[] RR)
        {
            RRData ret = new RRData();
            ret.byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) { ret.Name = ""; break; }
                ret.Name += (char)RR[i];
            }

            ret.Name = ret.Name.FromDNSName();

            ret.Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            ret.Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);
            ret.TTL = (uint)(RR[i + 5] * 0x1000000 + RR[i + 6]*0x10000 + RR[i + 7] * 0x100 + RR[i + 8]);
            ret.RDLength = (ushort)(RR[i + 9] * 0x100 + RR[i + 10]);
            ret.RDData=RR.Skip(i + 11).ToArray();

            if (ret.Type != QTYPES.OPT)
            {
                ret.OPTData = null;
            }
            else
            {
                ret.OPTData = ParseOPTData(ret.TTL);
            }

            //Console.WriteLine(JsonConvert.SerializeObject(ret.RDLength));
            //Console.WriteLine(JsonConvert.SerializeObject(ret.RDData));
            //Console.WriteLine(JsonConvert.SerializeObject(ret.OPTData));
            return ret;
        }

        private static RROPTData ParseOPTData(uint TTL)
        {
            RROPTData opt = new RROPTData();
            opt.RCODE = (ushort)(TTL / 0x1000000u);
            opt.VERSION = (ushort)(TTL % 0x1000000u / 0x10000u);
            opt.DO = TTL / 0x10000u % 0x80u == 1;
            opt.Z = (ushort)(TTL % 0x80u);
            return opt;
        }

        public static RRData BuildResponse_DNSKEY(byte[] RR, uint TTL, object[] data)
        {
            RRData ret = new RRData();
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

            int rdLen = 0;
            List<byte> rdData = new List<byte>();
            rdData.Add((byte)((uint)data[0] % 65536 / 256));
            rdData.Add((byte)((uint)data[0] % 256));

            rdData.Add((byte)(uint)data[1]);

            rdData.Add((byte)(uint)data[2]);

            string base64Key = data[3].ToString() + data[4].ToString();
            byte[] byteKey = Convert.FromBase64String(base64Key);

            for (var j = 0; j < byteKey.Length; j++)
            {
                rdData.Add((byte)(uint)byteKey[j]);
            }

            rdLen =rdData.Count;

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rdData[j]).ToArray();
            }

            return ret;
        }

        public static RRData BuildResponse_DS(byte[] RR, uint TTL, object[] data)
        {
            RRData ret = new RRData();
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

            int rdLen = 0;
            List<byte> rdData = new List<byte>();
            rdData.Add((byte)((uint)data[0] % 65536 / 256));
            rdData.Add((byte)((uint)data[0] % 256));

            rdData.Add((byte)(uint)data[1]);

            rdData.Add((byte)(uint)data[2]);

            string binKey = data[3].ToString() + data[4].ToString();

            for (var j = 0; j < binKey.Length; j+=2)
            {
                rdData.Add((byte)Convert.ToByte(binKey[j].ToString() + binKey[j + 1].ToString(),16));
            }

            rdLen = rdData.Count;

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rdData[j]).ToArray();
            }

            return ret;
        }

        public static RRData BuildResponse_RRSIG(byte[] RR,uint TTL,object[] data)
        {
            RRData ret = new RRData();
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

            int rdLen = 0;
            List<byte> rdData = new List<byte>();

            //RRSIG TYPE
            QTYPES RRSIGType = Enum.Parse<QTYPES>(data[0].ToString());
            rdData.Add((byte)((uint)RRSIGType % 65536 / 256));
            rdData.Add((byte)((uint)RRSIGType % 256));

            //RRSIG ALG
            rdData.Add((byte)(uint)data[1]);

            //RRSIG LABEL
            string signer = $@"{data[7]}".ToDNSName();
            rdData.Add((byte)(uint)data[2]);

            //RRSIG TTL
            uint rttl = (uint)data[3];

            rdData.Add((byte)(rttl / 16777216));
            rdData.Add((byte)(rttl % 16777216 / 65536));
            rdData.Add((byte)(rttl % 65536 / 256));
            rdData.Add((byte)(rttl % 256));

            //RRSIG EXP
            var dtreg = new Regex(@"^(\d{4,4})(\d{2,2})(\d{2,2})(\d{2,2})(\d{2,2})(\d{2,2})");
            DateTime dtr = DateTime.Parse(dtreg.Replace(data[4].ToString(), @"$1-$2-$3 $4:$5:$6"));
            uint sexp = (uint)(dtr - new DateTime(1970, 1, 1)).TotalSeconds;

            rdData.Add((byte)(sexp / 16777216));
            rdData.Add((byte)(sexp % 16777216 / 65536));
            rdData.Add((byte)(sexp % 65536 / 256));
            rdData.Add((byte)(sexp % 256));

            //RRSIG SIGTIME
            DateTime dts = DateTime.Parse(dtreg.Replace(data[5].ToString(), @"$1-$2-$3 $4:$5:$6"));
            uint ssig = (uint)(dts - new DateTime(1970, 1, 1)).TotalSeconds;

            rdData.Add((byte)(ssig / 16777216));
            rdData.Add((byte)(ssig % 16777216 / 65536));
            rdData.Add((byte)(ssig % 65536 / 256));
            rdData.Add((byte)(ssig % 256));

            //RRSIG TAG
            rdData.Add((byte)((uint)data[6] % 65536 / 256));
            rdData.Add((byte)((uint)data[6] % 256));

            //RRSIG SIGNER
            foreach(var c in signer)
            {
                rdData.Add((byte)c);
            }

            //RRSIG SIGNATURE
            string signature = $@"{data[8]}{data[9]}";
            byte[] byteKey = Convert.FromBase64String(signature);
            for (var j = 0; j < byteKey.Length; j++)
            {
                rdData.Add((byte)(uint)byteKey[j]);
            }

            rdLen = rdData.Count;

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rdData[j]).ToArray();
            }

            return ret;

        }

        public static RRData BuildResponse_NSEC(byte[] RR, uint TTL, object[] data)
        {
            RRData ret = new RRData();
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

            int rdLen = 0;
            List<byte> rdData = new List<byte>();

            //NSEC TAG
            var signer = data[0].ToString().ToDNSName();
            foreach (var c in signer)
            {
                rdData.Add((byte)c);
            }


            //NSEC TYPES
            byte[,] blocks = new byte[2,32];

            foreach (var q in data.Skip(1))
            {
                QTYPES t = (QTYPES)q;
                int v = (int)t;

                int windowNo = v / 256;
                int blockNo = (v % 256) / 8;
                int bitNo = 7 - (v % 256) % 8;

                blocks[windowNo, blockNo] |= (byte)Math.Pow(2, bitNo);
            }


            for (int wi = 0; wi < 2; wi++)
            {                

                int lastBlock = 31;
                bool found = false;

                for (int lb = lastBlock; lb >= 0; lb--)
                {
                    if (blocks[wi, lb] != 0)
                    {
                        lastBlock = lb; found = true; break;
                    }
                }

                if (!found) break;

                rdData.Add((byte)wi);
                rdData.Add((byte)(lastBlock + 1));
                for (int r0 = 0; r0 < lastBlock + 1; r0++)
                {
                    rdData.Add(blocks[wi, r0]);
                }

            }


            rdLen = rdData.Count;

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rdData[j]).ToArray();
            }

            return ret;
        }

        public static RRData BuildResponse_NSEC3PARAM(byte[] RR, uint TTL, object[] data)
        {
            RRData ret = new RRData();
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

            int rdLen = 0;
            List<byte> rdData = new List<byte>();

            rdData.Add((byte)(uint)data[0]);
            rdData.Add((byte)(uint)data[1]);
            rdData.Add((byte)((uint)data[2] / 256));
            rdData.Add((byte)((uint)data[2] % 256));

            string salt = data[3].ToString();

            rdData.Add((byte)(salt.Length / 2));

            for (var j = 0; j < salt.Length; j += 2)
            {
                rdData.Add((byte)Convert.ToByte(salt[j].ToString() + salt[j + 1].ToString(), 16));
            }

            rdLen = rdData.Count;

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rdData[j]).ToArray();
            }

            return ret;
        }

        public static RRData BuildResponse_NSEC3(byte[] RR, uint TTL, object[] data)
        {
            RRData ret = new RRData();
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

            int rdLen = 0;
            List<byte> rdData = new List<byte>();

            rdData.Add((byte)(uint)data[0]);
            rdData.Add((byte)(uint)data[1]);
            rdData.Add((byte)((uint)data[2] / 256));
            rdData.Add((byte)((uint)data[2] % 256));

            string salt = data[3].ToString();

            rdData.Add((byte)(salt.Length / 2));

            for (var j = 0; j < salt.Length; j += 2)
            {
                rdData.Add((byte)Convert.ToByte(salt[j].ToString() + salt[j + 1].ToString(), 16));
            }

            string hash = data[4].ToString();
            byte[] nextHashedOwnerName = Base32.FromBase32HexString(hash);

            byte[] bhash = nextHashedOwnerName;

            rdData.Add((byte)bhash.Length);

            rdData.AddRange(bhash);

            //NSEC3 TYPES
            byte[,] blocks = new byte[2, 32];

            foreach (var q in data.Skip(5))
            {
                QTYPES t = (QTYPES)q;
                int v = (int)t;

                int windowNo = v / 256;
                int blockNo = (v % 256) / 8;
                int bitNo = 7 - (v % 256) % 8;

                blocks[windowNo, blockNo] |= (byte)Math.Pow(2, bitNo);
            }


            for (int wi = 0; wi < 2; wi++)
            {

                int lastBlock = 31;
                bool found = false;

                for (int lb = lastBlock; lb >= 0; lb--)
                {
                    if (blocks[wi, lb] != 0)
                    {
                        lastBlock = lb; found = true; break;
                    }
                }

                if (!found) break;

                rdData.Add((byte)wi);
                rdData.Add((byte)(lastBlock + 1));
                for (int r0 = 0; r0 < lastBlock + 1; r0++)
                {
                    rdData.Add(blocks[wi, r0]);
                }

            }

            rdLen = rdData.Count;

            //RD Length
            ret.byteData = ret.byteData.Append((byte)(rdLen / 256)).ToArray();
            ret.byteData = ret.byteData.Append((byte)(rdLen % 256)).ToArray();

            for (var j = 0; j < rdLen; j++)
            {
                ret.byteData = ret.byteData.Append(rdData[j]).ToArray();
            }

            return ret;
        }
    }

    public class RROPTData
    {
        public ushort RCODE { get; set; }
        public ushort VERSION { get; set; }
        public bool DO { get; set; }
        public ushort Z { get; set; }

    }
}

