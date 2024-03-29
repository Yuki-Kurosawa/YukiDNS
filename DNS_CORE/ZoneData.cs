﻿using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Collections.Generic;
using YukiDNS.DNS_RFC;

namespace YukiDNS.DNS_CORE
{
    public class ZoneData
    {

        public string Name { get; set; }

        public uint TTL { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public QTYPES Type { get; set; }

        public object[] Data { get; set; }

        public string ZoneName { get; set; }

        public ZoneData RRSIG { get; set; }

        public string NSEC3Name { get; set; }
    
    }

    public class ZoneArea
    {
        private string _Name;

        public ZoneArea(string Name) 
        {
            _Name = Name;
        }
        public string Name
        {
            get { return _Name; }
        }

        public List<ZoneData> Data { get; set; } = new List<ZoneData>();
    }
}