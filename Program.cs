using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using YukiDNS.DNS_CORE;
using YukiDNS.CA_CORE;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using YukiDNS.HTTP_CORE;
using System.Threading;

namespace YukiDNS
{
    class Program
    {
        static Thread WebService = null;

        static void Main(string[] args)
        {
            //Load Configs
            DNSService.LoadConfig();
            DNSService.LoadZoneFiles();
            CA_Program.LoadConfig();

            //Start Services
            //DNSService.Start();
            StartWebServer(args);


            Console.WriteLine("All Service Started");


            Console.ReadLine();
        }

        public static void StartWebServer(string[] args)
        {
            if (WebService == null)
            {
                WebService = new Thread(() =>
                {
                    try
                    { 
                        CreateHostBuilder(args).Build().Run();
                    }
                    catch
                    {
                        WebService = null;
                    }
                });

                WebService.Start();
            }
        }


        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            return Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                    webBuilder.UseKestrel(options =>
                    {
                        options.AllowSynchronousIO = true;
                    });
                });
        }
    }
}

