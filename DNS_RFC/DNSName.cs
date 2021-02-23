using System;
using System.Collections.Generic;
using System.Linq;

namespace YukiDNS.DNS_RFC
{
    public static class DNSName
    {
        public static string ToDNSName(this string name)
        {
            string iname = name;
            if (iname.Last() != '.')
            {
                iname += ".";
            }
            string ret = "", tmp = "";

            int i = 0;
            for (int c = 0; c < iname.Length; c++)
            {
                if (iname[c] != '.')
                {
                    i++;
                    tmp += iname[c];
                }
                else
                {
                    ret += (char)i + tmp;
                    tmp = "";
                    i = 0;
                }
            }

            ret += (char)0;

            return ret;
        }

        public static string FromDNSName(this string dname)
        {
            string ret = "", tmp = "";

            int i = 0, id = 0;
            bool dot = true;

            for (int c = 0; c < dname.Length; c++)
            {
                if (dot)
                {
                    i = dname[c];
                    id = 0;
                    dot = false;
                    tmp = "";
                }
                else
                {
                    tmp += dname[c];
                    id++;
                    if (id == i)
                    {
                        ret += tmp + ".";
                        dot = true;
                    }
                }
            }

            return ret.TrimEnd('.');
        }

    }

}

