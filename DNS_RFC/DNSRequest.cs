﻿using System;
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

        public bool IsAuthority { get; set; }//1 AA

        public bool Truncated { get; set; }//1 TC

        public bool RecursionDesired { get; set; }//1 RD

        public bool RecursionAccepted { get; set; }//1 RA

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

        public RRData[] RRAnswer { get; set; }

        public RRData[] RRAuthority { get; set; }

        public RRData[] RRAdditional { get; set; }

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
            ParseRR(1,ref ret, ref data);
            ParseRR(2,ref ret, ref data);
            ParseRR(3,ref ret, ref data);
            ParseRR(4,ref ret, ref data);


            return ret;
        }

        private static void ParseRR(int RRSection,ref DNSRequest ret, ref byte[] data)
        {
            if(RRSection==1)
            {
                List<RRQuery> rs = new List<RRQuery>();
                for (int i = 0; i < ret.Query; i++)
                {
                    RRStruct rr = new RRStruct(data);
                    rs.Add(new RRQuery(rr.byteData));
                    data = new List<byte>(data.Skip(rr.byteData.Length)).ToArray();
                }
                ret.RRQueries = rs.ToArray();
            }
            else if (RRSection == 2)
            {
                List<RRData> rs = new List<RRData>();
                for (int i = 0; i < ret.Answer; i++)
                {
                    RRStruct rr = new RRStruct(data);
                    rs.Add(RRData.ParseRequest(rr.byteData));
                    data = new List<byte>(data.Skip(rr.byteData.Length)).ToArray();
                }
                ret.RRAnswer = rs.ToArray();
            }
            else if (RRSection == 3)
            {
                List<RRData> rs = new List<RRData>();
                for (int i = 0; i < ret.Authority; i++)
                {
                    RRStruct rr = new RRStruct(data);
                    rs.Add(RRData.ParseRequest(rr.byteData));
                    data = new List<byte>(data.Skip(rr.byteData.Length)).ToArray();
                }
                ret.RRAuthority = rs.ToArray();
            }
            else if(RRSection==4)
            {
                List<RRData> rs = new List<RRData>();
                for (int i = 0; i < ret.Addtional; i++)
                {
                    RRStruct rr = new RRStruct(data);
                    rs.Add(RRData.ParseRequest(rr.byteData));
                    data = new List<byte>(data.Skip(rr.byteData.Length)).ToArray();
                }
                ret.RRAdditional = rs.ToArray();
            }
        }

        public byte[] To()
        {
            List<byte> ret = new List<byte>();
            ret.Add((byte)(TransactionID / 256));
            ret.Add((byte)(TransactionID % 256));


            //FLAGS
            ushort Flags = 0;
            Flags |= (ushort)(IsResponse ? 32768 : 0);
            Flags |= (ushort)((ushort)OpCode * 2048);
            Flags |= (ushort)(IsAuthority ? 1024 : 0);
            Flags |= (ushort)(Truncated ? 512 : 0);
            Flags |= (ushort)(RecursionDesired ? 256 : 0);
            Flags |= (ushort)(RecursionAccepted ? 128 : 0);
            Flags |= (ushort)(Z ? 64 : 0);
            Flags |= (ushort)(Authed ? 32 : 0);
            Flags |= (ushort)(AuthData ? 16 : 0);
            Flags |= (ushort)ReplyCode;


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
  
}