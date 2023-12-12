using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

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

        public RRQuery ChangeQueryType(QTYPES type,string cname="")
        {
            var nq = this.Copy();
            {

                nq.Type = type;
                byte[] bd = new byte[nq.byteData.Length];
                nq.byteData.CopyTo(bd, 0);
                nq.byteData = bd;

                int k = 0;
                for (; k < nq.byteData.Length; k++)
                {
                    if (nq.byteData[k] == 0) break;
                    //ret.Name += (char)RR[i];
                }

                string rn = cname;
                List<byte> bn = new List<byte>();

                foreach (string r in rn.Split(new[] { "." }, StringSplitOptions.RemoveEmptyEntries))
                {
                    byte[] br = Encoding.ASCII.GetBytes(r);
                    bn.Add((byte)br.Length);
                    bn.AddRange(br);
                }

                var bl = nq.byteData.Skip(k).ToArray();
                List<byte> al = new List<byte>();

                al.AddRange(bn);
                al.AddRange(bl);
                nq.byteData = al.ToArray();

                k = 0;
                for (; k < nq.byteData.Length; k++)
                {
                    if (nq.byteData[k] == 0) break;
                    //ret.Name += (char)RR[i];
                }

                nq.byteData[k + 1] = (byte)(((int)nq.Type) / 256);
                nq.byteData[k + 2] = (byte)(((int)nq.Type) % 256);

            }

            return nq;
        }
    }

}
