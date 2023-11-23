using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YukiDNS.CA_CORE
{
    public class AIAConfig
    {
        /// <summary>
        /// 
        /// </summary>
        public bool UseAIA { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string CAIssuer { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string OCSPMethod { get; set; }
    }

    public class CA_Config
    {
        /// <summary>
        /// 
        /// </summary>
        public int KeySize { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string SignMethod { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public int SelfSignCACertExpire { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public int CACertExpire { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public int EndUserCertExpire { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public AIAConfig AIAConfig { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string CertDir { get; set; }

        public string DefaultSelfSignCAName { get; set; }

        public string DefaultCAName { get; set; }

        public string DefaultEndUserName { get; set; }
    }

}
