using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using YukiDNS.DNS_RFC;

namespace YukiDNS.DNS_CORE
{
    public static class ZoneParser
    {
        public static ZoneData ParseLine(string line)
        {
            string[] args = line.Split(new string[] { "\t", " " }, StringSplitOptions.RemoveEmptyEntries);

            string name = args[0];
            uint ttl = uint.Parse(args[1]);
            QTYPES type=(QTYPES)Enum.Parse(typeof(QTYPES), args[3]);

            byte[] rrb = new byte[1] { (byte)'.'};

            switch (type)
            {
                case QTYPES.A:
                case QTYPES.AAAA:
                case QTYPES.NS:
                case QTYPES.PTR:
                case QTYPES.CNAME:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { args[4] }
                    };
                case QTYPES.MX:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { ushort.Parse(args[4]), args[5] }
                    };
                case QTYPES.TXT:
                case QTYPES.SPF:
                    string argv = "";

                    foreach(var v in args.Skip(4))
                    {
                        argv += v + " ";
                    }

                    argv=argv.Trim();
                    argv=argv.Trim('"');

                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { argv }
                    };
                case QTYPES.SRV:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { ushort.Parse(args[4]), ushort.Parse(args[5]), ushort.Parse(args[6]), args[7] }
                    };
                case QTYPES.CAA:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { ushort.Parse(args[4]), args[5], args[6] }
                    };
                case QTYPES.SOA:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] {  args[4], args[5], uint.Parse(args[6]), uint.Parse(args[7]), uint.Parse(args[8]), uint.Parse(args[9]), uint.Parse(args[10]) }
                    };
                default:
                    throw new Exception("RR Data Format Error");
            }

        }
    }
}
