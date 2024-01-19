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

namespace YukiDNS
{
    class Program
    {

        static void Main(string[] args)
        {
            if (args[0] == "dns")
            {
                DNSService.Start();
            }
            else if (args[0] == "zone")
            {
                string[] data = File.ReadAllLines(@"zones\e1.ksyuki.com.flat.zone");

                ZoneArea zone = ZoneParser.ParseArea("e1.ksyuki.com", data);

                List<ZoneData> list = zone.Data;

                foreach (var data1 in list)
                {
                    Console.WriteLine(JsonConvert.SerializeObject(data1));
                }

                Console.ReadLine();
            }
            else if (args[0] == "http")
            {
                CreateHostBuilder(args).Build().Run();
            }
            else
            {
                CA_Program.Main(args.Skip(1).ToArray());
            }
        }


        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>()
                .UseUrls("http://*:5000")
                ;
                });
    }
}

