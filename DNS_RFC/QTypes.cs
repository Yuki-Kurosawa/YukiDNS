using System;
using System.Collections.Generic;
using System.Linq;

namespace YukiDNS.DNS_RFC
{
    public enum QTYPES
    {
        NONE = 0,
        ANY = 255,
        A = 1,
        AAAA = 28,
        CAA = 257,
        CNAME = 5,
        MX = 15,
        NS = 2,
        PTR = 12,
        SOA = 6,
        SPF = 99,
        SRV = 33,
        TXT = 16,
        OPT = 41,

        //USE FOR DNSSEC
        DNSKEY=48,
        RRSIG=46,
        NSEC=47,
        DS=43,
        NSEC3=50,
        NSEC3PARAM=51
    }
}

