using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using Newtonsoft.Json;

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

            if(ret.Type!=QTYPES.OPT)
            {
                ret.OPTData = null;
            }
            else
            {
                ret.OPTData = ParseOPTData(ret.TTL);
            }

            Console.WriteLine(JsonConvert.SerializeObject(ret.RDLength));
            Console.WriteLine(JsonConvert.SerializeObject(ret.RDData));
            Console.WriteLine(JsonConvert.SerializeObject(ret.OPTData));
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
    

    }

    public class RROPTData
    {
        public ushort RCODE { get; set; }
        public ushort VERSION { get; set; }
        public bool DO { get; set; }
        public ushort Z { get; set; }

    }
}

