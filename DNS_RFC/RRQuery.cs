using System;
using System.Collections.Generic;
using System.Linq;

namespace YukiDNS.DNS_RFC
{
   
    public class RRQuery
    {
        public byte[] byteData { get; set; }

        public string Name { get; private set; }

        public QTYPES Type { get; set; }

        public RRClass Class { get; private set; }

        private RRQuery()
        {

        }

        public RRQuery(byte[] RR)
        {
            byteData = RR;
            int i = 0;
            for (; i < RR.Length; i++)
            {
                if (RR[i] == 0) { Name = ""; break; }
                Name += (char)RR[i];
            }

            Name = Name.FromDNSName();

            Type = (QTYPES)(RR[i + 1] * 0x100 + RR[i + 2]);
            Class = (RRClass)(RR[i + 3] * 0x100 + RR[i + 4]);
        }

        public RRQuery Copy()
        {
            RRQuery obj = new RRQuery();
            foreach (var p in obj.GetType().GetProperties())
            {
                p.SetValue(obj, p.GetValue(this));
            }
            return obj;
        }
    }

}
