using System;
using System.IO;
using System.Text;

namespace YukiDNS.COMMON_CORE
{
    public class ConsoleLogHelper
    {
        public static void WriteInfoLine(string message, bool setHeader = true)
        {
            WriteLine((setHeader ? GetHeader("I: ") : "") + message);
        }

        public static void WriteInfo(string message, bool setHeader = true)
        {
            Write((setHeader ? GetHeader("I: ") : "") + message);
        }

        public static void WriteErrorLine(string message, bool setHeader = true)
        {
            WriteLine((setHeader ? GetHeader("E: ") : "") + message);
        }

        public static void WriteError(string message, bool setHeader = true)
        {
            Write((setHeader ? GetHeader("E: ") : "") + message);
        }

        public static void WriteWarnLine(string message, bool setHeader = true)
        {
            WriteLine((setHeader ? GetHeader("W: ") : "") + message);
        }

        public static void WriteWarn(string message, bool setHeader = true)
        {
            Write((setHeader ? GetHeader("W: ") : "") + message);
        }

        private static string GetHeader(string name)
        {
            return $@"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {name}";
        }

        private static void WriteLine(string message)
        {
            Console.WriteLine(message);
            File.AppendAllText("log.txt", message + "\r\n", Encoding.UTF8);
        }

        private static void Write(string message)
        {
            Console.Write(message);
            File.AppendAllText("log.txt", message, Encoding.UTF8);
        }
    }
}
