using System;
using System.Collections.Generic;
using System.Linq;

namespace YukiDNS.DNS_RFC
{
    public enum ReplyCode : ushort
    {
        NOERROR, FORMERR, SERVFAIL,
        NXDOMAIN, NOTIMP, REFUSED,
        YXDOMAIN, YXRRSET, NXRRSET,
        NOTAUTH, NOTZONE, RESERVED11,
        RESERVED12, RESERVED13, RESERVED14,
        RESERVED15
    }
}
