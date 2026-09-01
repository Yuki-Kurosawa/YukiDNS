using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace YukiDNS.CA_CORE
{
    /// <summary>
    /// SQLite 证书库 + 策略库：
    /// - certificates：证书持久化、全局唯一序列号、吊销状态、密钥类型（RSA/EC）。
    /// - policies：签发策略（密钥类型/参数、有效期、签名算法、AIA），可扩展；Init 时种入默认 RSA/EC。
    /// </summary>
    public static class CA_DB
    {
        private static string _connStr;
        private static readonly object _lock = new object();
        private static bool _inited;

        public static void Init(string dbPath)
        {
            if (string.IsNullOrEmpty(dbPath)) throw new ArgumentException("CA Database path is empty");
            string full = Path.GetFullPath(dbPath);
            string dir = Path.GetDirectoryName(full);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            _connStr = "Data Source=" + full;

            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS certificates (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    serial        TEXT NOT NULL UNIQUE,
    kind          TEXT NOT NULL,
    subject       TEXT NOT NULL,
    issuer_serial TEXT,
    is_ca         INTEGER NOT NULL DEFAULT 0,
    san           TEXT,
    cert_path     TEXT NOT NULL,
    key_path      TEXT,
    not_before    TEXT,
    not_after     TEXT,
    status        TEXT NOT NULL DEFAULT 'valid',
    revoke_reason TEXT,
    revoked_at    TEXT,
    created_at    TEXT NOT NULL,
    key_type      TEXT,
    key_params    TEXT,
    policy_id     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_certs_issuer ON certificates(issuer_serial);
CREATE INDEX IF NOT EXISTS idx_certs_kind    ON certificates(kind);

CREATE TABLE IF NOT EXISTS policies (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    key_type          TEXT NOT NULL,
    key_params        TEXT NOT NULL,
    sign_algo         TEXT,
    ca_validity_days  INTEGER NOT NULL,
    leaf_validity_days INTEGER NOT NULL,
    use_aia           INTEGER NOT NULL DEFAULT 1,
    key_usage         TEXT,
    ext_usage_oids    TEXT,
    cert_type         TEXT,
    validation        TEXT,
    is_internal       INTEGER NOT NULL DEFAULT 0,
    extra             TEXT
);

CREATE TABLE IF NOT EXISTS oid_names (
    oid         TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT
);";
                cmd.ExecuteNonQuery();

                // 防御性迁移：老库补列
                EnsureColumn(c, "certificates", "key_type", "TEXT");
                EnsureColumn(c, "certificates", "key_params", "TEXT");
                EnsureColumn(c, "certificates", "policy_id", "INTEGER");
                EnsureColumn(c, "policies", "key_usage", "TEXT");
                EnsureColumn(c, "policies", "ext_usage_oids", "TEXT");
                EnsureColumn(c, "policies", "cert_type", "TEXT");
                EnsureColumn(c, "policies", "validation", "TEXT");
                EnsureColumn(c, "policies", "is_internal", "INTEGER NOT NULL DEFAULT 0");
                EnsureColumn(c, "policies", "extra", "TEXT");

                SeedDefaultPolicies(c);
                _inited = true;
            }
        }

        private static void EnsureColumn(SqliteConnection c, string table, string column, string decl)
        {
            var cols = new HashSet<string>();
            using (var cmd = c.CreateCommand())
            {
                cmd.CommandText = "PRAGMA table_info(" + table + ")";
                using var r = cmd.ExecuteReader();
                while (r.Read()) cols.Add(r.GetString(1));
            }
            if (!cols.Contains(column))
            {
                using var cmd = c.CreateCommand();
                cmd.CommandText = "ALTER TABLE " + table + " ADD COLUMN " + column + " " + decl;
                cmd.ExecuteNonQuery();
            }
        }

        /// <summary>库为空时种入三类用途策略（按“这签的是什么证书”划分，而非密钥类型；内部自用策略由用户按需自建）。</summary>
        private static void SeedDefaultPolicies(SqliteConnection c)
        {
            using var chk = c.CreateCommand();
            chk.CommandText = "SELECT COUNT(*) FROM policies";
            long cnt = (long)chk.ExecuteScalar();
            if (cnt > 0) return;

            var seed = new[]
            {
                // Web TLS：正常 HTTPS 服务器证书
                new { name = "Web TLS", keyType = "RSA", keyParams = "2048", signAlgo = "SHA256withRSA", ca = 1825, leaf = 90,
                      ku = "digitalSignature,keyEncipherment", eku = "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",
                      certType = "web", validation = "DV", isInternal = 0 },
                // 邮件 / 客户端：S/MIME 与客户端认证
                new { name = "邮件/客户端", keyType = "RSA", keyParams = "2048", signAlgo = "SHA256withRSA", ca = 1825, leaf = 365,
                      ku = "digitalSignature,keyEncipherment,dataEncipherment", eku = "1.3.6.1.5.5.7.3.4,1.3.6.1.5.5.7.3.2",
                      certType = "email-client", validation = "DV", isInternal = 0 },
                // 代码签名
                new { name = "代码签名", keyType = "RSA", keyParams = "2048", signAlgo = "SHA256withRSA", ca = 1825, leaf = 365,
                      ku = "digitalSignature", eku = "1.3.6.1.5.5.7.3.3",
                      certType = "code-signing", validation = "DV", isInternal = 0 },
            };
            foreach (var p in seed)
            {
                using var cmd = c.CreateCommand();
                cmd.CommandText = @"INSERT INTO policies (name, key_type, key_params, sign_algo, ca_validity_days, leaf_validity_days, use_aia, key_usage, ext_usage_oids, cert_type, validation, is_internal)
                                    VALUES (@n,@t,@k,@s,@ca,@leaf,1,@ku,@eku,@ct,@val,@in)";
                cmd.Parameters.AddWithValue("@n", p.name);
                cmd.Parameters.AddWithValue("@t", p.keyType);
                cmd.Parameters.AddWithValue("@k", p.keyParams);
                cmd.Parameters.AddWithValue("@s", p.signAlgo);
                cmd.Parameters.AddWithValue("@ca", p.ca);
                cmd.Parameters.AddWithValue("@leaf", p.leaf);
                cmd.Parameters.AddWithValue("@ku", p.ku);
                cmd.Parameters.AddWithValue("@eku", p.eku);
                cmd.Parameters.AddWithValue("@ct", p.certType);
                cmd.Parameters.AddWithValue("@val", p.validation);
                cmd.Parameters.AddWithValue("@in", p.isInternal);
                cmd.ExecuteNonQuery();
            }
        }

        private static SqliteConnection Open()
        {
            var conn = new SqliteConnection(_connStr);
            conn.Open();
            return conn;
        }

        private static void EnsureInit()
        {
            if (!_inited) Init("certs/ca.db");
        }

        // ---------- 序列号 ----------

        public static string GenerateSerial()
        {
            byte[] bytes = new byte[16];
            RandomNumberGenerator.Fill(bytes);
            bytes[0] &= 0x7F;
            if (bytes[0] == 0) bytes[0] = 1;
            return new BigInteger(1, bytes).ToString(16).ToUpperInvariant();
        }

        public static string NormalizeSerial(string serial)
        {
            if (string.IsNullOrEmpty(serial)) return serial;
            string s = serial.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
            s = s.TrimStart('0');
            return string.IsNullOrEmpty(s) ? "0" : s.ToUpperInvariant();
        }

        public static BigInteger SerialToBigInteger(string serial)
        {
            string s = NormalizeSerial(serial);
            return s == "0" ? BigInteger.Zero : new BigInteger(s, 16);
        }

        public static string BigIntegerToSerial(BigInteger bi)
        {
            return bi.ToString(16).ToUpperInvariant();
        }

        // ---------- 证书 ----------

        public static void Insert(CertRecord rec)
        {
            EnsureInit();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = @"
INSERT INTO certificates
    (serial, kind, subject, issuer_serial, is_ca, san, cert_path, key_path,
     not_before, not_after, status, revoke_reason, revoked_at, created_at,
     key_type, key_params, policy_id)
VALUES
    (@serial, @kind, @subject, @issuer_serial, @is_ca, @san, @cert_path, @key_path,
     @not_before, @not_after, @status, @revoke_reason, @revoked_at, @created_at,
     @key_type, @key_params, @policy_id)";
                cmd.Parameters.AddWithValue("@serial", rec.Serial);
                cmd.Parameters.AddWithValue("@kind", rec.Kind);
                cmd.Parameters.AddWithValue("@subject", rec.Subject);
                cmd.Parameters.AddWithValue("@issuer_serial", (object)rec.IssuerSerial ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@is_ca", rec.IsCA ? 1 : 0);
                cmd.Parameters.AddWithValue("@san", (object)rec.San ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@cert_path", rec.CertPath);
                cmd.Parameters.AddWithValue("@key_path", (object)rec.KeyPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@not_before", rec.NotBefore?.ToString("o") ?? (object)DBNull.Value);
                cmd.Parameters.AddWithValue("@not_after", rec.NotAfter?.ToString("o") ?? (object)DBNull.Value);
                cmd.Parameters.AddWithValue("@status", rec.Status ?? "valid");
                cmd.Parameters.AddWithValue("@revoke_reason", (object)rec.RevokeReason ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@revoked_at", rec.RevokedAt?.ToString("o") ?? (object)DBNull.Value);
                cmd.Parameters.AddWithValue("@created_at", DateTime.UtcNow.ToString("o"));
                cmd.Parameters.AddWithValue("@key_type", (object)rec.KeyType ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@key_params", (object)rec.KeyParams ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@policy_id", rec.PolicyId.HasValue ? (object)rec.PolicyId.Value : DBNull.Value);
                cmd.ExecuteNonQuery();
            }
        }

        public static CertRecord GetBySerial(string serial)
        {
            EnsureInit();
            if (string.IsNullOrEmpty(serial)) return null;
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM certificates WHERE serial = @serial";
                cmd.Parameters.AddWithValue("@serial", NormalizeSerial(serial));
                using var r = cmd.ExecuteReader();
                return r.Read() ? ReadRecord(r) : null;
            }
        }

        public static CertRecord GetRoot()
        {
            EnsureInit();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM certificates WHERE kind = 'root' ORDER BY id LIMIT 1";
                using var r = cmd.ExecuteReader();
                return r.Read() ? ReadRecord(r) : null;
            }
        }

        public static List<CertRecord> GetRoots()
        {
            EnsureInit();
            var list = new List<CertRecord>();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM certificates WHERE kind = 'root' ORDER BY id";
                using var r = cmd.ExecuteReader();
                while (r.Read()) list.Add(ReadRecord(r));
            }
            return list;
        }

        public static List<CertRecord> ListByIssuer(string issuerSerial)
        {
            EnsureInit();
            var list = new List<CertRecord>();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM certificates WHERE issuer_serial = @issuer ORDER BY id";
                cmd.Parameters.AddWithValue("@issuer", issuerSerial);
                using var r = cmd.ExecuteReader();
                while (r.Read()) list.Add(ReadRecord(r));
            }
            return list;
        }

        public static List<CertRecord> ListAll()
        {
            EnsureInit();
            var list = new List<CertRecord>();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM certificates ORDER BY id";
                using var r = cmd.ExecuteReader();
                while (r.Read()) list.Add(ReadRecord(r));
            }
            return list;
        }

        public static void Revoke(string serial, string reason)
        {
            EnsureInit();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = @"
UPDATE certificates
SET status = 'revoked', revoke_reason = @reason, revoked_at = @at
WHERE serial = @serial AND status <> 'revoked'";
                cmd.Parameters.AddWithValue("@serial", NormalizeSerial(serial));
                cmd.Parameters.AddWithValue("@reason", (object)reason ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@at", DateTime.UtcNow.ToString("o"));
                cmd.ExecuteNonQuery();
            }
        }

        // ---------- 策略 ----------

        public static PolicyRecord GetPolicyById(long id)
        {
            EnsureInit();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM policies WHERE id = @id";
                cmd.Parameters.AddWithValue("@id", id);
                using var r = cmd.ExecuteReader();
                return r.Read() ? ReadPolicy(r) : null;
            }
        }

        public static PolicyRecord GetPolicyByName(string name)
        {
            EnsureInit();
            if (string.IsNullOrEmpty(name)) return null;
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM policies WHERE name = @name";
                cmd.Parameters.AddWithValue("@name", name);
                using var r = cmd.ExecuteReader();
                return r.Read() ? ReadPolicy(r) : null;
            }
        }

        public static List<PolicyRecord> ListPolicies()
        {
            EnsureInit();
            var list = new List<PolicyRecord>();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM policies ORDER BY id";
                using var r = cmd.ExecuteReader();
                while (r.Read()) list.Add(ReadPolicy(r));
            }
            return list;
        }

        /// <summary>插入新策略，返回新记录。</summary>
        public static PolicyRecord InsertPolicy(PolicyRecord p)
        {
            EnsureInit();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = @"
INSERT INTO policies (name, key_type, key_params, sign_algo, ca_validity_days, leaf_validity_days, use_aia, key_usage, ext_usage_oids, cert_type, validation, is_internal)
VALUES (@n,@t,@k,@s,@ca,@leaf,@aia,@ku,@eku,@ct,@val,@in);
SELECT last_insert_rowid();";
                cmd.Parameters.AddWithValue("@n", p.Name);
                cmd.Parameters.AddWithValue("@t", p.KeyType);
                cmd.Parameters.AddWithValue("@k", p.KeyParams);
                cmd.Parameters.AddWithValue("@s", (object)p.SignAlgo ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@ca", p.CaValidityDays);
                cmd.Parameters.AddWithValue("@leaf", p.LeafValidityDays);
                cmd.Parameters.AddWithValue("@aia", p.UseAIA ? 1 : 0);
                cmd.Parameters.AddWithValue("@ku", (object)p.KeyUsage ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@eku", (object)p.ExtUsageOids ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@ct", string.IsNullOrEmpty(p.CertType) ? (object)"custom" : p.CertType);
                cmd.Parameters.AddWithValue("@val", (object)p.Validation ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@in", p.Internal ? 1 : 0);
                long id = (long)cmd.ExecuteScalar();
                return GetPolicyById(id);
            }
        }

        /// <summary>更新策略（仅更新给定字段）。</summary>
        public static void UpdatePolicy(long id, string name, string keyType, string keyParams, string signAlgo,
            int? caValidityDays, int? leafValidityDays, bool? useAIA, string keyUsage, string extUsageOids,
            string certType, string validation, bool? isInternal)
        {
            EnsureInit();
            var existing = GetPolicyById(id) ?? throw new InvalidOperationException("Policy not found: " + id);
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = @"
UPDATE policies SET
    name = @n, key_type = @t, key_params = @k, sign_algo = @s,
    ca_validity_days = @ca, leaf_validity_days = @leaf, use_aia = @aia,
    key_usage = @ku, ext_usage_oids = @eku,
    cert_type = @ct, validation = @val, is_internal = @in
WHERE id = @id";
                cmd.Parameters.AddWithValue("@id", id);
                cmd.Parameters.AddWithValue("@n", string.IsNullOrEmpty(name) ? existing.Name : name);
                cmd.Parameters.AddWithValue("@t", string.IsNullOrEmpty(keyType) ? existing.KeyType : keyType);
                cmd.Parameters.AddWithValue("@k", string.IsNullOrEmpty(keyParams) ? existing.KeyParams : keyParams);
                cmd.Parameters.AddWithValue("@s", signAlgo != null ? (object)signAlgo : (object)existing.SignAlgo ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@ca", caValidityDays ?? existing.CaValidityDays);
                cmd.Parameters.AddWithValue("@leaf", leafValidityDays ?? existing.LeafValidityDays);
                cmd.Parameters.AddWithValue("@aia", (useAIA ?? existing.UseAIA) ? 1 : 0);
                cmd.Parameters.AddWithValue("@ku", keyUsage != null ? (object)keyUsage : (object)existing.KeyUsage ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@eku", extUsageOids != null ? (object)extUsageOids : (object)existing.ExtUsageOids ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@ct", certType != null ? (object)certType : (object)existing.CertType ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@val", validation != null ? (object)validation : (object)existing.Validation ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@in", isInternal ?? existing.Internal ? 1 : 0);
                cmd.ExecuteNonQuery();
            }
        }

        /// <summary>删除策略；若被证书记录引用则拒绝。</summary>
        public static void DeletePolicy(long id)
        {
            EnsureInit();
            lock (_lock)
            {
                using (var c = Open())
                using (var cmd = c.CreateCommand())
                {
                    cmd.CommandText = "SELECT COUNT(*) FROM certificates WHERE policy_id = @id";
                    cmd.Parameters.AddWithValue("@id", id);
                    long refs = (long)cmd.ExecuteScalar();
                    if (refs > 0)
                        throw new InvalidOperationException("Policy is referenced by " + refs + " certificate(s); cannot delete.");
                }
                using var del = Open();
                using var cmd2 = del.CreateCommand();
                cmd2.CommandText = "DELETE FROM policies WHERE id = @id";
                cmd2.Parameters.AddWithValue("@id", id);
                cmd2.ExecuteNonQuery();
            }
        }

        // ---------- OID 可读名 ----------

        public static OidNameRecord GetOidName(string oid)
        {
            EnsureInit();
            if (string.IsNullOrEmpty(oid)) return null;
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT oid, name, description FROM oid_names WHERE oid = @oid";
                cmd.Parameters.AddWithValue("@oid", oid.Trim());
                using var r = cmd.ExecuteReader();
                if (!r.Read()) return null;
                return new OidNameRecord
                {
                    Oid = r.GetString(0),
                    Name = r.GetString(1),
                    Description = r.IsDBNull(2) ? null : r.GetString(2),
                    BuiltIn = false
                };
            }
        }

        /// <summary>列出全部自定义（非内置）OID 注册项。</summary>
        public static List<OidNameRecord> ListCustomOidNames()
        {
            EnsureInit();
            var list = new List<OidNameRecord>();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT oid, name, description FROM oid_names ORDER BY oid";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    list.Add(new OidNameRecord
                    {
                        Oid = r.GetString(0),
                        Name = r.GetString(1),
                        Description = r.IsDBNull(2) ? null : r.GetString(2),
                        BuiltIn = false
                    });
                }
            }
            return list;
        }

        /// <summary>新增或覆盖 OID 可读名（存在则更新）。</summary>
        public static OidNameRecord UpsertOidName(string oid, string name, string description)
        {
            EnsureInit();
            if (string.IsNullOrWhiteSpace(oid) || string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("oid and name are required.");
            string o = oid.Trim();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = @"
INSERT INTO oid_names (oid, name, description) VALUES (@oid, @name, @desc)
ON CONFLICT(oid) DO UPDATE SET name = @name, description = @desc;";
                cmd.Parameters.AddWithValue("@oid", o);
                cmd.Parameters.AddWithValue("@name", name.Trim());
                cmd.Parameters.AddWithValue("@desc", (object)description ?? DBNull.Value);
                cmd.ExecuteNonQuery();
            }
            return GetOidName(o);
        }

        /// <summary>删除自定义 OID 注册项；oid 本身是内置 OID 时仅回退到内置名（删除 DB 覆盖）。</summary>
        public static void DeleteOidName(string oid)
        {
            EnsureInit();
            lock (_lock)
            {
                using var c = Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "DELETE FROM oid_names WHERE oid = @oid";
                cmd.Parameters.AddWithValue("@oid", oid.Trim());
                cmd.ExecuteNonQuery();
            }
        }

        // ---------- 读取辅助 ----------

        private static CertRecord ReadRecord(SqliteDataReader r)
        {
            var rec = new CertRecord
            {
                Id = r.GetInt64(r.GetOrdinal("id")),
                Serial = r.GetString(r.GetOrdinal("serial")),
                Kind = r.GetString(r.GetOrdinal("kind")),
                Subject = r.GetString(r.GetOrdinal("subject")),
                IsCA = r.GetInt64(r.GetOrdinal("is_ca")) == 1,
                CertPath = r.GetString(r.GetOrdinal("cert_path")),
                Status = r.GetString(r.GetOrdinal("status")),
            };
            rec.IssuerSerial = ReadNullableString(r, "issuer_serial");
            rec.San = ReadNullableString(r, "san");
            rec.KeyPath = ReadNullableString(r, "key_path");
            rec.NotBefore = ParseDate(r, "not_before");
            rec.NotAfter = ParseDate(r, "not_after");
            rec.RevokeReason = ReadNullableString(r, "revoke_reason");
            rec.RevokedAt = ParseDate(r, "revoked_at");
            rec.CreatedAt = ParseDate(r, "created_at") ?? DateTime.UtcNow;
            rec.KeyType = ReadNullableString(r, "key_type");
            rec.KeyParams = ReadNullableString(r, "key_params");
            rec.PolicyId = r.IsDBNull(r.GetOrdinal("policy_id")) ? (long?)null : r.GetInt64(r.GetOrdinal("policy_id"));
            return rec;
        }

        private static PolicyRecord ReadPolicy(SqliteDataReader r)
        {
            return new PolicyRecord
            {
                Id = r.GetInt64(r.GetOrdinal("id")),
                Name = r.GetString(r.GetOrdinal("name")),
                KeyType = r.GetString(r.GetOrdinal("key_type")),
                KeyParams = r.GetString(r.GetOrdinal("key_params")),
                SignAlgo = ReadNullableString(r, "sign_algo"),
                CaValidityDays = (int)r.GetInt64(r.GetOrdinal("ca_validity_days")),
                LeafValidityDays = (int)r.GetInt64(r.GetOrdinal("leaf_validity_days")),
                UseAIA = r.GetInt64(r.GetOrdinal("use_aia")) == 1,
                KeyUsage = ReadNullableString(r, "key_usage"),
                ExtUsageOids = ReadNullableString(r, "ext_usage_oids"),
                CertType = ReadNullableString(r, "cert_type"),
                Validation = ReadNullableString(r, "validation"),
                Internal = r.GetInt64(r.GetOrdinal("is_internal")) == 1,
                Extra = ReadNullableString(r, "extra"),
            };
        }

        private static string ReadNullableString(SqliteDataReader r, string col)
        {
            int idx = r.GetOrdinal(col);
            return r.IsDBNull(idx) ? null : r.GetString(idx);
        }

        private static DateTime? ParseDate(SqliteDataReader r, string col)
        {
            int idx = r.GetOrdinal(col);
            if (r.IsDBNull(idx)) return null;
            return DateTime.TryParse(r.GetString(idx), null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt) ? dt : (DateTime?)null;
        }
    }
}
