using System;

namespace YukiDNS.CA_CORE
{
    /// <summary>证书记录：SQLite 中一行 = 一张已签发/已存在的证书（CA 或叶子）。</summary>
    public class CertRecord
    {
        public long Id { get; set; }

        /// <summary>全局唯一序列号（十六进制大写，随机 128-bit）。</summary>
        public string Serial { get; set; }

        /// <summary>root | ca | leaf</summary>
        public string Kind { get; set; }

        /// <summary>证书 Subject（X500 格式）。</summary>
        public string Subject { get; set; }

        /// <summary>直接签发者的序列号；root 为 null。</summary>
        public string IssuerSerial { get; set; }

        public bool IsCA { get; set; }

        /// <summary>叶子证书的 SAN（逗号分隔），CA 为 null。</summary>
        public string San { get; set; }

        /// <summary>证书 PEM 落盘路径。</summary>
        public string CertPath { get; set; }

        /// <summary>私钥 PEM 落盘路径（仅服务端生成时存在；CSR 模式为 null，密钥由请求方自持）。</summary>
        public string KeyPath { get; set; }

        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }

        /// <summary>valid | revoked</summary>
        public string Status { get; set; }

        public string RevokeReason { get; set; }
        public DateTime? RevokedAt { get; set; }
        public DateTime CreatedAt { get; set; }

        /// <summary>本证书密钥类型：RSA | EC。</summary>
        public string KeyType { get; set; }

        /// <summary>密钥参数：RSA 为位数（如 2048），EC 为曲线名（如 P-256）。</summary>
        public string KeyParams { get; set; }

        /// <summary>引用的策略 id（CA 记录用于约束链，叶子继承签发者策略）。</summary>
        public long? PolicyId { get; set; }

        /// <summary>签发者记录（由链回溯填充），root 为 null。</summary>
        public CertRecord Issuer { get; set; }
    }

    /// <summary>
    /// 签发策略（存于数据库 policies 表，可扩展——未来新增策略类型通过 extra JSON 或其他列承载）。
    /// </summary>
    public class PolicyRecord
    {
        public long Id { get; set; }
        public string Name { get; set; }

        /// <summary>RSA | EC</summary>
        public string KeyType { get; set; }

        /// <summary>RSA 位数 / EC 曲线名，如 2048、P-256</summary>
        public string KeyParams { get; set; }

        /// <summary>签名算法（如 SHA256withRSA / SHA256withECDSA），为空时按密钥类型自动推导。</summary>
        public string SignAlgo { get; set; }

        public int CaValidityDays { get; set; }
        public int LeafValidityDays { get; set; }

        /// <summary>签发时是否写入 AIA / CDP 扩展。</summary>
        public bool UseAIA { get; set; }

        /// <summary>KeyUsage 位名列表（逗号分隔，如 digitalSignature,keyEncipherment）。空 = 签发时按证书用途默认。</summary>
        public string KeyUsage { get; set; }

        /// <summary>ExtendedKeyUsage OID 列表（逗号分隔，如 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2）。空 = 签发时按证书用途默认；CA 证书默认不设 EKU。</summary>
        public string ExtUsageOids { get; set; }

        /// <summary>证书用途类型：web | email-client | code-signing | custom。策略按“这签的是什么证书”划分，而非密钥类型。</summary>
        public string CertType { get; set; }

        /// <summary>验证种类（标识用途）：DV | OV | EV。本系统不做自动化验证，仅作为策略语义与将来对接标识。</summary>
        public string Validation { get; set; }

        /// <summary>内部自用证书策略（不对外，仅内部使用）。</summary>
        public bool Internal { get; set; }

        /// <summary>预留扩展（JSON），未来新策略字段放这里。</summary>
        public string Extra { get; set; }
    }

    /// <summary>签发操作的结果：序列号 + 证书 PEM 内容 + 记录。</summary>
    public class CertIssueResult
    {
        public CertRecord Record { get; set; }
        public string CertPEM { get; set; }
    }

    // ---------- HTTP 请求模型 ----------

    /// <summary>建根：Policy 为策略名（如 Web TLS / 代码签名），空则默认 Web TLS。KeyType/KeyParams 可选覆盖策略的默认密钥参数（用于建 EC 根等）。</summary>
    public class InitRootCARequest
    {
        public string Name { get; set; }
        public string Policy { get; set; }
        public string KeyType { get; set; }
        public string KeyParams { get; set; }
    }

    /// <summary>
    /// 建 CA：
    /// - 传 CSR：按 CSR 密钥类型签发（必须与父 CA 同类型），此时必须指定 ParentSerial。
    /// - 不传 CSR 且 ParentSerial 为空：按 Policy 新建根（KeyType/KeyParams 可覆盖）。
    /// - 不传 CSR 且 ParentSerial 非空：服务端生成与父 CA 同类型密钥的下一级 CA。
    /// </summary>
    public class CreateCARequest
    {
        public string Name { get; set; }
        public string ParentSerial { get; set; }
        public string CSR { get; set; }
        public string Policy { get; set; }
        public string KeyType { get; set; }
        public string KeyParams { get; set; }
    }

    /// <summary>兼容旧接口：CAName 视为父 CA 序列号。</summary>
    public class Layer2Request
    {
        public string Name { get; set; }
        public string CAName { get; set; }
    }

    /// <summary>服务端自生成密钥的叶子签发（私钥落盘不返回）。IssuerSerial 为空默认取首个根。</summary>
    public class WebServerCertRequest
    {
        public string Name { get; set; }
        public string DNSNames { get; set; }
        public string IssuerSerial { get; set; }
    }

    /// <summary>CSR 模式签发叶子：密钥由请求方自持，CA 只签公钥。IssuerSerial 为空按 CSR 密钥类型自动路由。</summary>
    public class SignCSRRequest
    {
        public string CSR { get; set; }
        public string IssuerSerial { get; set; }
        public string Name { get; set; }
        public string DNSNames { get; set; }
    }

    public class RevokeRequest
    {
        public string Serial { get; set; }
        public string Reason { get; set; }
    }

    /// <summary>创建 / 更新签发策略的请求体。</summary>
    public class PolicyRequest
    {
        public string Name { get; set; }
        public string KeyType { get; set; }          // RSA | EC
        public string KeyParams { get; set; }        // 位数 / 曲线名
        public string SignAlgo { get; set; }         // 空 = 按密钥类型自动推导
        public int? CaValidityDays { get; set; }
        public int? LeafValidityDays { get; set; }
        public bool? UseAIA { get; set; }
        public string KeyUsage { get; set; }         // 逗号分隔 KeyUsage 位名
        public string ExtUsageOids { get; set; }     // 逗号分隔 EKU OID
        public string CertType { get; set; }         // web | email-client | code-signing | custom
        public string Validation { get; set; }       // DV | OV | EV
        public bool? Internal { get; set; }
    }

    /// <summary>OID → 可读名的注册项（oid_names 表 + 内置默认）。</summary>
    public class OidNameRecord
    {
        public string Oid { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        /// <summary>是否内置（内置项仅可覆盖、不可删除）。</summary>
        public bool BuiltIn { get; set; }
    }

    /// <summary>创建 / 更新 OID 可读名的请求体。</summary>
    public class OidNameRequest
    {
        public string Oid { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
    }
}
