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
        public static ZoneData ParseLine(string line,string zoneName)
        {
            string[] args = line.Split(new string[] { "\t", " " }, StringSplitOptions.RemoveEmptyEntries);

            string name = args[0];
            uint ttl = uint.Parse(args[1]);
            QTYPES type=(QTYPES)Enum.Parse(typeof(QTYPES), args[3]);

            if (name.Contains(zoneName + "."))
            {
                name = name.Replace(zoneName + ".", "").Trim('.');
            }

            if(string.IsNullOrEmpty(name))
            {
                name = "@";
            }

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
                        Data = new object[] { args[4] },
                        ZoneName = zoneName
                    };
                case QTYPES.MX:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { ushort.Parse(args[4]), args[5] },
                        ZoneName = zoneName
                    };
                case QTYPES.TXT:
                case QTYPES.SPF:
                    string argv = "";

                    foreach (var v in args.Skip(4))
                    {
                        argv += v + " ";
                    }

                    argv = argv.Trim();
                    argv = argv.Trim('"');

                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { argv },
                        ZoneName = zoneName
                    };
                case QTYPES.SRV:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { ushort.Parse(args[4]), ushort.Parse(args[5]), ushort.Parse(args[6]), args[7] },
                        ZoneName = zoneName
                    };
                case QTYPES.CAA:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { ushort.Parse(args[4]), args[5], args[6] },
                        ZoneName = zoneName
                    };
                case QTYPES.SOA:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { args[4], args[5], uint.Parse(args[6]), uint.Parse(args[7]), uint.Parse(args[8]), uint.Parse(args[9]), uint.Parse(args[10]) },
                        ZoneName = zoneName
                    };
                case QTYPES.DNSKEY:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { uint.Parse(args[4]), uint.Parse(args[5]), uint.Parse(args[6]), args[7], args[8] },
                        ZoneName = zoneName
                    };
                case QTYPES.DS:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { uint.Parse(args[4]), uint.Parse(args[5]), uint.Parse(args[6]), args[7], args[8] },
                        ZoneName = zoneName
                    };
                case QTYPES.RRSIG:
                    return new ZoneData()
                    {
                        Name = name,
                        TTL = ttl,
                        Type = type,
                        Data = new object[] { Enum.Parse<QTYPES>(args[4]), uint.Parse(args[5]), uint.Parse(args[6]), uint.Parse(args[7]), args[8], args[9], uint.Parse(args[10]), args[11], args[12], args[13] },
                        ZoneName = zoneName
                    };
                default:
                    throw new Exception("RR Data Format Error");
            }

        }
    }
}
