using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
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
                name = name.Replace(zoneName + ".", "").Trim('.').ToLower();
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
                case QTYPES.NSEC:
                    {
                        var data = new ZoneData()
                        {
                            Name = name,
                            TTL = ttl,
                            Type = type,
                            ZoneName = zoneName
                        };
                        var objects=new List<object>();
                        objects.Add(args[4]);
                        foreach (var obj in args.Skip(5))
                        {
                            objects.Add(Enum.Parse<QTYPES>(obj));
                        }
                        data.Data = objects.ToArray();
                        return data;
                    }
                case QTYPES.NSEC3PARAM:
                    {
                        var data = new ZoneData()
                        {
                            Name = name,
                            TTL = ttl,
                            Type = type,
                            ZoneName = zoneName
                        };
                        var objects = new List<object>();
                        objects.Add(uint.Parse(args[4]));
                        objects.Add(uint.Parse(args[5]));
                        objects.Add(uint.Parse(args[6]));
                        objects.Add(args[7]);
                        data.Data = objects.ToArray();
                        return data;
                    }
                case QTYPES.NSEC3:
                    {
                        var data = new ZoneData()
                        {
                            Name = name,
                            TTL = ttl,
                            Type = type,
                            ZoneName = zoneName
                        };
                        var objects = new List<object>();
                        objects.Add(uint.Parse(args[4]));
                        objects.Add(uint.Parse(args[5]));
                        objects.Add(uint.Parse(args[6]));
                        objects.Add(args[7]);
                        objects.Add(args[8]);
                        foreach (var obj in args.Skip(9))
                        {
                            objects.Add(Enum.Parse<QTYPES>(obj));
                        }
                        data.Data = objects.ToArray();
                        return data;
                    }
                default:
                    throw new Exception("RR Data Format Error");
            }

        }
    
        public static ZoneArea ParseArea(string zoneName, string[] zoneData)
        {
            ZoneArea zone = new ZoneArea(zoneName);

            foreach (string line in zoneData)
            {
                var rrLine = new Regex("[;]{1,}.*$").Replace(line, string.Empty);// Remove All Comments From RR Data Lines
                if (string.IsNullOrEmpty(rrLine)) continue;

                var line2 = line.Replace("\t", " ");

                while (line2.Contains("  "))
                {
                    line2 = line2.Replace("  ", " ");
                }

                try
                {
                    ZoneData data1 = ZoneParser.ParseLine(line2, zoneName);
                    if (data1.Type != QTYPES.RRSIG)
                    {
                        zone.Data.Add(data1);
                    }
                    else
                    {
                        var ql = zone.Data.Where(q => q.Type == (QTYPES)data1.Data[0] && q.Name == data1.Name).ToList();
                        if (ql.Count > 0)
                        {
                            ql[0].RRSIG = data1;
                        }
                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message + ":" + line2.Split(' ')[3]);
                }

                
            }

            if (zone.Data.Count > 0)
            {
                //Add NSEC3 Name
                List<ZoneData> nsec3rrs = zone.Data.Where(q => q.Type == QTYPES.NSEC3).ToList();

                if (nsec3rrs.Count > 0)
                {

                    string current = zone.Data[0].Name;
                    int nsec3index = 0;
                    for (int i = 0; i < zone.Data.Count; i++)
                    {
                        if (zone.Data[i].Type == QTYPES.NSEC3) continue;

                        if (zone.Data[i].Name== current)
                        {
                            zone.Data[i].NSEC3Name = nsec3rrs[nsec3index].Name;
                        }
                        else
                        {
                            current = zone.Data[i].Name;
                            nsec3index++;
                            zone.Data[i].NSEC3Name = nsec3rrs[nsec3index].Name;
                        }
                    }
                }
            }

            return zone;
        }
    }
}
