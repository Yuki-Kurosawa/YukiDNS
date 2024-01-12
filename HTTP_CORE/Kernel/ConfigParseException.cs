using System;
using System.Runtime.Serialization;

namespace YukiDNS.HTTP_CORE.Kernel
{
    [Serializable]
    public class ConfigParseException : Exception
    {
        public string message { get; }

        public string siteConf { get; }
        public int line { get; }

        public ConfigParseException()
        {
        }

        public ConfigParseException(string message) : base(message)
        {
        }

        public ConfigParseException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public ConfigParseException(string message, string siteConf, int line)
        {
            this.message = message;
            this.siteConf = siteConf;
            this.line = line;
        }

        protected ConfigParseException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}