using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace YukiDNS.MAIL_CORE
{
    // 一封邮件在 IMAP 邮箱中的表示
    public class IMAPMessage
    {
        public string Uidl { get; set; }         // 文件名（不含 .eml），兼作稳定标识
        public string FilePath { get; set; }
        public long Uid { get; set; }
        public List<string> Flags { get; set; } = new List<string>();
        public long Size { get; set; }

        private byte[] _raw;
        public byte[] GetRaw()
        {
            if (_raw == null) _raw = File.ReadAllBytes(FilePath);
            return _raw;
        }
    }

    // 一个 IMAP 邮箱 = maildb 下的一个目录。INBOX 为用户主目录，子文件夹为子目录。
    // UID / UIDVALIDITY / 邮件标志通过 sidecar JSON 持久化。
    public class IMAPMailbox
    {
        private const string MailboxRootPath = "maildb";
        private const string MetaFile = ".imap_meta.json";
        private const string FlagsFile = ".imap_flags.json";

        public string Name { get; private set; }
        public string DirectoryPath { get; private set; }
        public List<IMAPMessage> Messages { get; private set; } = new List<IMAPMessage>();
        public long UidValidity { get; private set; }
        public long UidNext { get; private set; }

        private class Meta
        {
            public long uidvalidity { get; set; }
            public long uidnext { get; set; }
            public Dictionary<string, long> uids { get; set; } = new Dictionary<string, long>();
        }

        private Meta _meta = new Meta();
        private bool _metaDirty = false;

        public static string HomeDirPath(string user)
        {
            string dirName = POP3Service.MailBoxesToDirName(user);
            return Path.Combine(MailboxRootPath, dirName ?? "");
        }

        public static string MailboxDirPath(string name, string user)
        {
            string home = HomeDirPath(user);
            if (string.IsNullOrEmpty(name) || string.Equals(name, "INBOX", StringComparison.OrdinalIgnoreCase))
            {
                return home;
            }
            string rel = name;
            if (rel.StartsWith("INBOX/", StringComparison.OrdinalIgnoreCase))
            {
                rel = rel.Substring("INBOX/".Length);
            }
            // reject path traversal: subfolders are single-level plain names (no .. or separators)
            if (string.IsNullOrEmpty(rel) || rel.Contains("..") ||
                rel.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                rel.Contains('/') || rel.Contains('\\'))
            {
                return null;
            }
            return Path.Combine(home, rel);
        }

        /// <summary>打开一个邮箱；目录不存在时返回 null。</summary>
        public static IMAPMailbox Open(string name, string user)
        {
            string path = MailboxDirPath(name, user);
            if (!Directory.Exists(path)) return null;

            IMAPMailbox mb = new IMAPMailbox
            {
                Name = name,
                DirectoryPath = path
            };
            mb.LoadMeta();
            mb.LoadMessages();
            mb.SaveMetaIfDirty();
            return mb;
        }

        /// <summary>列出用户的邮箱（INBOX + 子目录）。</summary>
        public static List<string> ListMailboxes(string user)
        {
            List<string> names = new List<string>();
            string home = HomeDirPath(user);
            if (!Directory.Exists(home)) return names;

            names.Add("INBOX");
            foreach (string dir in Directory.GetDirectories(home))
            {
                string n = Path.GetFileName(dir);
                if (n.StartsWith(".")) continue; // 跳过 sidecar/隐藏目录
                names.Add("INBOX/" + n);
            }
            return names;
        }

        private void LoadMeta()
        {
            string p = Path.Combine(DirectoryPath, MetaFile);
            if (File.Exists(p))
            {
                try
                {
                    _meta = JsonSerializer.Deserialize<Meta>(File.ReadAllText(p)) ?? new Meta();
                }
                catch
                {
                    _meta = new Meta();
                }
            }
            else
            {
                _meta = new Meta();
                _meta.uidvalidity = RandomUidValidity();
                _meta.uidnext = 1;
                _metaDirty = true;
            }
            UidValidity = _meta.uidvalidity;
            UidNext = _meta.uidnext;
        }

        private void LoadMessages()
        {
            Messages = new List<IMAPMessage>();
            Dictionary<string, List<string>> flags = LoadFlags();

            string[] files = Directory.GetFiles(DirectoryPath, "*.eml")
                .OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal)
                .ToArray();

            foreach (string f in files)
            {
                string uidl = Path.GetFileNameWithoutExtension(f);
                long uid;
                if (!_meta.uids.TryGetValue(uidl, out uid))
                {
                    uid = _meta.uidnext++;
                    _meta.uids[uidl] = uid;
                    _metaDirty = true;
                }

                IMAPMessage msg = new IMAPMessage
                {
                    Uidl = uidl,
                    FilePath = f,
                    Uid = uid,
                    Size = new FileInfo(f).Length
                };
                if (flags.TryGetValue(uidl, out List<string> fl)) msg.Flags = fl;
                Messages.Add(msg);
            }

            Messages.Sort((a, b) => a.Uid.CompareTo(b.Uid));
            UidNext = _meta.uidnext;
        }

        private Dictionary<string, List<string>> LoadFlags()
        {
            string p = Path.Combine(DirectoryPath, FlagsFile);
            if (File.Exists(p))
            {
                try
                {
                    return JsonSerializer.Deserialize<Dictionary<string, List<string>>>(File.ReadAllText(p)) ?? new Dictionary<string, List<string>>();
                }
                catch
                {
                }
            }
            return new Dictionary<string, List<string>>();
        }

        public int SeqOf(IMAPMessage m) => Messages.IndexOf(m) + 1;

        public int UnseenCount()
        {
            return Messages.Count(m => !m.Flags.Contains("\\Seen"));
        }

        public IMAPMessage FirstUnseen()
        {
            return Messages.FirstOrDefault(m => !m.Flags.Contains("\\Seen"));
        }

        public void SaveFlags()
        {
            Dictionary<string, List<string>> map = new Dictionary<string, List<string>>();
            foreach (IMAPMessage m in Messages)
            {
                if (m.Flags.Count > 0) map[m.Uidl] = m.Flags;
            }
            File.WriteAllText(Path.Combine(DirectoryPath, FlagsFile), JsonSerializer.Serialize(map), new UTF8Encoding(false));
        }

        private void SaveMeta()
        {
            _meta.uidnext = UidNext;
            File.WriteAllText(Path.Combine(DirectoryPath, MetaFile), JsonSerializer.Serialize(_meta), new UTF8Encoding(false));
        }

        private void SaveMetaIfDirty()
        {
            if (_metaDirty) SaveMeta();
        }

        /// <summary>删除一条消息（文件 + UID 映射 + 标志），用于 EXPUNGE/CLOSE。</summary>
        public void DeleteMessage(IMAPMessage m)
        {
            Messages.Remove(m);
            if (File.Exists(m.FilePath)) File.Delete(m.FilePath);
            _meta.uids.Remove(m.Uidl);
            SaveMeta();
            SaveFlags();
        }

        /// <summary>向邮箱追加一条消息（APPEND）。</summary>
        public IMAPMessage AppendMessage(byte[] raw, List<string> flags)
        {
            string uidl = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid().ToString().Substring(0, 8)}";
            string path = Path.Combine(DirectoryPath, uidl + ".eml");
            File.WriteAllBytes(path, raw);

            long uid = _meta.uidnext++;
            _meta.uids[uidl] = uid;
            IMAPMessage msg = new IMAPMessage
            {
                Uidl = uidl,
                FilePath = path,
                Uid = uid,
                Size = raw.Length,
                Flags = flags ?? new List<string>()
            };
            Messages.Add(msg);
            Messages.Sort((a, b) => a.Uid.CompareTo(b.Uid));
            UidNext = _meta.uidnext;
            SaveMeta();
            SaveFlags();
            return msg;
        }

        private static long RandomUidValidity()
        {
            return (long)(new Random().Next(1, int.MaxValue)) * 1000L + DateTime.UtcNow.Ticks % 1000L;
        }
    }
}
