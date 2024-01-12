using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Web.Util;

namespace System.Web
{
    public static class HttpUtility
    {
        public static string UrlDecode(string str,Encoding encoding)
        {
            return HttpEncoder.Default.UrlDecode(str, encoding);
        }

        public static string UrlEncode(string str, Encoding encoding)
        {
            return HttpEncoder.Default.UrlEncodeNonAscii(str, encoding);
        }

        public static string UrlDecode(string str)
        {
            return UrlDecode(str,Encoding.UTF8);
        }

        public static string UrlEncode(string str)
        {
            return UrlEncode(str,Encoding.UTF8);
        }
    }
}
