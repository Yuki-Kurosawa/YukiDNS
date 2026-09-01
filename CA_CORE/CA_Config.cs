namespace YukiDNS.CA_CORE
{
    /// <summary>
    /// CA 服务级配置（ca.json）。
    /// 签发策略（密钥类型/参数、有效期、AIA、签名算法）已迁入数据库 policies 表。
    /// </summary>
    public class CA_Config
    {
        /// <summary>证书/私钥落盘目录。</summary>
        public string CertDir { get; set; }

        /// <summary>SQLite 证书库文件路径。</summary>
        public string Database { get; set; }

        /// <summary>对外服务 Base URL，用于拼接 AIA / CDP 中的签发者证书、OCSP、CRL 地址。</summary>
        public string BaseURL { get; set; }

        /// <summary>默认 Subject 模板（策略与证书签名不在此配置）。</summary>
        public string DefaultSelfSignCAName { get; set; }
        public string DefaultCAName { get; set; }
        public string DefaultEndUserName { get; set; }
    }
}
