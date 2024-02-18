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
using YukiDNS.ACME_CORE;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel;

namespace YukiDNS
{
    class Program
    {
        static Thread WebService = null;
        static IHost WebHost = null;

        static void Main(string[] args)
        {
            //Load Configs
            DNSService.LoadConfig();
            DNSService.LoadZoneFiles();
            CA_Service.LoadConfig();

            //Start Services
            DNSService.Start();
            StartWebServer(args);


            Console.WriteLine("All Service Started");
            //ACMEService.Start();


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
                        WebHost = CreateHostBuilder(args).Build();
                        WebHost.Run();
                    }
                    catch
                    {
                        WebService = null;
                        WebHost = null;
                    }
                });

                WebService.Start();
            }
        }

        public static void StopWebServer(string[] args)
        {
            if (WebService != null)
            {
                WebHost.StopAsync().Wait();
                WebHost = null;
                WebService = null;
            }
        }


        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            return Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                    webBuilder.UseKestrel((builder,options) =>
                    { 
                        options.AllowSynchronousIO = true;
                        options.Configure(builder.Configuration.GetSection("Kestrel"),reloadOnChange: true);
                    });

                    IConfiguration kconfig = new ConfigurationBuilder()
                    .AddJsonFile("kconfig.json")
                    .AddEnvironmentVariables()
                    .Build();

                    webBuilder.UseConfiguration(kconfig);
                });
        }
    }
}

