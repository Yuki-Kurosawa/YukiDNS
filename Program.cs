using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using YukiDNS.DNS_CORE;

namespace YukiDNS
{
    class Program
    {        

        static void Main(string[] args)
        {
            if(args[0]=="dns"){
                DNSService.Start();
            }
        }       
    }
}
