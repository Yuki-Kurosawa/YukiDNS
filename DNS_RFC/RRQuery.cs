using System;
using System.Collections.Generic;
using System.Linq;

namespace YukiDNS.DNS_RFC
{
   
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

}
