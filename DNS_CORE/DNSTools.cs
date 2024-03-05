using System;
using System.IO;
using YukiDNS.COMMON_CORE;
using static System.Net.Mime.MediaTypeNames;

namespace YukiDNS.DNS_CORE
{
    public class DNSTools
    {
        public static bool CheckZone(string zoneName, string zoneFile)
        {
            string binPath = Path.Combine(DNSService.config.ToolsDir, "named-checkzone");
            int ret = ExtToolRunner.Run(binPath, new string[] { zoneName, zoneFile });

            return ret == 0;
        }

        public static bool SignZone(string zoneName, string zoneFile,string zoneKey, string salt)
        {
            string binPath = Path.Combine(DNSService.config.ToolsDir, "dnssec-signzone");

            string[] signArgs = string.IsNullOrEmpty(salt) ?
            [
                "-K",".","-d", ".", "-P", "-g" ,"-o", zoneName, zoneFile, zoneKey
            ] :
            [
                "-K",".","-d", ".","-3",salt,"-AA", "-P", "-g" ,"-o", zoneName, zoneFile,zoneKey
            ];

            string workDir=new FileInfo(Path.Combine("zones","put_zone_files_here.txt")).Directory.FullName;

            int ret = ExtToolRunner.RunEx(workDir, binPath, signArgs);

            return ret == 0;
        }

        public static bool FlatZone(string zoneName, string zoneFile)
        {
            string binPath = Path.Combine(DNSService.config.ToolsDir, "named-compilezone");

            string[] signArgs = ["-F", "text", "-o", zoneFile+".flat", "-s", "full", zoneName, zoneFile];

            string workDir = new FileInfo(Path.Combine("zones", "put_zone_files_here.txt")).Directory.FullName;

            int ret = ExtToolRunner.RunEx(workDir, binPath, signArgs);

            return ret == 0;
        }
    }
}