using System;
using System.Diagnostics;

namespace YukiDNS.COMMON_CORE
{
    public class ExtToolRunner
    {

        public static string Output = "",Error="";

        public static int Run(string toolPath, string[] args)
        {
            if(Environment.OSVersion.Platform == PlatformID.Win32NT) 
            {
                toolPath = toolPath + ".exe";
            }

            Output = "";
            Error = "";

            ProcessStartInfo psi=new ProcessStartInfo(toolPath,ParseArgs(args));
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            Process p=Process.Start(psi);
            p.ErrorDataReceived += P_ErrorDataReceived;
            p.OutputDataReceived += P_OutputDataReceived;
            p.BeginErrorReadLine();
            p.BeginOutputReadLine();

            p.WaitForExit();

            int ret = p.ExitCode;

            return ret;

        }

        public static int RunEx(string workDir, string toolPath, string[] args)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                toolPath = toolPath + ".exe";
            }

            Output = "";
            Error = "";

            ProcessStartInfo psi = new ProcessStartInfo(toolPath, ParseArgs(args));
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.WorkingDirectory = workDir;

            Process p = Process.Start(psi);
            p.ErrorDataReceived += P_ErrorDataReceived;
            p.OutputDataReceived += P_OutputDataReceived;
            p.BeginErrorReadLine();
            p.BeginOutputReadLine();

            p.WaitForExit();

            int ret = p.ExitCode;

            return ret;

        }

        private static void P_OutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            Output += e.Data + Environment.NewLine;
        }

        private static void P_ErrorDataReceived(object sender, DataReceivedEventArgs e)
        {
            Error += e.Data + Environment.NewLine;
        }

        private static string ParseArgs(string[] args)
        {
            string argStr = "";
            foreach (string arg in args)
            {
                argStr += $@"{arg} ";
            }

            argStr=argStr.Trim();

            return argStr;
        }
    }
}
