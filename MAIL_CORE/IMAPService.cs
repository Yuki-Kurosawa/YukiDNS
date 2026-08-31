using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using MimeKit;

namespace YukiDNS.MAIL_CORE
{
    public enum ImapState
    {
        NotAuthenticated,
        Authenticated,
        Selected
    }

    // 解析后的 IMAP 命令
    public class ImapCommand
    {
        public string Tag;
        public string Name;
        public List<object> Args = new List<object>(); // string 或 byte[]（字面量）
    }

    public class IMAPService
    {
        private const int Port = 143;
        private const int MaxCommandBytes = 1 << 20; // 1MB，防止超长命令

        public static void Start()
        {
            Thread imap = new Thread(IMAP_THREAD_TCP);
            imap.IsBackground = true;
            imap.Start();
            Console.WriteLine("IMAPService started, listening on port 143...");
        }

        private static void IMAP_THREAD_TCP()
        {
            TcpListener server = null;
            try
            {
                server = new TcpListener(IPAddress.Any, Port);
                server.Start();

                while (true)
                {
                    TcpClient client = server.AcceptTcpClient();
                    Thread clientThread = new Thread(() => HandleClient(client));
                    clientThread.IsBackground = true;
                    clientThread.Start();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
            finally
            {
                if (server != null) server.Stop();
            }
        }

        private class Session
        {
            public NetworkStream Stream;
            public ImapState State = ImapState.NotAuthenticated;
            public string User;
            public IMAPMailbox Mailbox;          // 已 SELECT 的邮箱
            public bool ReadOnly;
        }

        private static void HandleClient(TcpClient client)
        {
            Session session = new Session();
            try
            {
                session.Stream = client.GetStream();
                Write(session.Stream, "* OK [CAPABILITY IMAP4rev1 UIDPLUS] YukiDNS IMAP server ready");

                while (true)
                {
                    ImapCommand cmd = ReadCommand(session.Stream);
                    if (cmd == null) break; // 连接关闭
                    if (!Dispatch(session, cmd)) break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("IMAP session exception: {0}", e.Message);
            }
            finally
            {
                try { client.Close(); } catch { }
                Console.WriteLine("IMAP connection closed.");
            }
        }

        #region 命令读取与解析

        private static string ReadLine(NetworkStream stream)
        {
            List<byte> buf = new List<byte>();
            int b;
            while ((b = stream.ReadByte()) != -1)
            {
                if (b == (byte)'\n') break;
                if (b != (byte)'\r') buf.Add((byte)b);
            }
            if (b == -1 && buf.Count == 0) return null;
            if (buf.Count > MaxCommandBytes) throw new Exception("command too long");
            return Encoding.UTF8.GetString(buf.ToArray());
        }

        private static byte[] ReadBytes(NetworkStream stream, int n)
        {
            byte[] data = new byte[n];
            int got = 0;
            while (got < n)
            {
                int r = stream.Read(data, got, n - got);
                if (r <= 0) break;
                got += r;
            }
            if (got != n) throw new Exception("unexpected end of literal");
            return data;
        }

        // 读取一条命令（支持 RFC 3501 §4.3 字面量）
        // Read one command (RFC 3501 section 4.3 literal support).
        // A literal is always the final argument (APPEND data), so nothing is read after it.
        private static ImapCommand ReadCommand(NetworkStream stream)
        {
            while (true)
            {
                string line = ReadLine(stream);
                if (line == null) return null;
                if (line.Length == 0) continue; // skip stray CRLF (some clients send one after a literal)

                List<object> tokens = new List<object>();
                foreach (string p in SplitArgs(line))
                {
                    Match m = Regex.Match(p, @"^\{(\d+)\}$");
                    if (m.Success)
                    {
                        int n = int.Parse(m.Groups[1].Value);
                        if (n > MaxCommandBytes) throw new Exception("literal too large");
                        Write(stream, "+ Ready for literal data");
                        tokens.Add(ReadBytes(stream, n));
                    }
                    else
                    {
                        tokens.Add(p);
                    }
                }

                if (tokens.Count < 2) continue;

                string name = ((string)tokens[1]).ToUpperInvariant();
                int argStart = 2;
                if (name == "UID" && tokens.Count >= 3)
                {
                    name = "UID " + ((string)tokens[2]).ToUpperInvariant();
                    argStart = 3;
                }

                return new ImapCommand
                {
                    Tag = (string)tokens[0],
                    Name = name,
                    Args = tokens.Skip(argStart).ToList()
                };
            }
        }
private static List<string> SplitArgs(string line)
        {
            List<string> result = new List<string>();
            StringBuilder cur = new StringBuilder();
            bool inQuote = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"' && !inQuote)
                {
                    inQuote = true;
                    cur.Append(c);
                }
                else if (c == '"' && inQuote)
                {
                    if (i > 0 && line[i - 1] == '\\')
                    {
                        cur.Append(c);
                    }
                    else
                    {
                        inQuote = false;
                        cur.Append(c);
                    }
                }
                else if (char.IsWhiteSpace(c) && !inQuote)
                {
                    if (cur.Length > 0) { result.Add(cur.ToString()); cur.Clear(); }
                }
                else
                {
                    cur.Append(c);
                }
            }
            if (cur.Length > 0) result.Add(cur.ToString());
            return result;
        }

        private static string Unquote(string s)
        {
            if (s == null) return null;
            if (s.Length >= 2 && s[0] == '"' && s[s.Length - 1] == '"')
            {
                s = s.Substring(1, s.Length - 2);
                s = s.Replace("\\\"", "\"").Replace("\\\\", "\\");
            }
            return s;
        }

        #endregion

        #region 命令分发

        private static bool Dispatch(Session session, ImapCommand cmd)
        {
            string tag = cmd.Tag;
            string name = cmd.Name;

            switch (name)
            {
                case "CAPABILITY":
                    Write(session.Stream, "* CAPABILITY IMAP4rev1 UIDPLUS");
                    Write(session.Stream, $"{tag} OK CAPABILITY completed");
                    break;
                case "NOOP":
                    Write(session.Stream, $"{tag} OK NOOP completed");
                    break;
                case "LOGOUT":
                    Write(session.Stream, "* BYE YukiDNS IMAP server logging out");
                    Write(session.Stream, $"{tag} OK LOGOUT completed");
                    return false;
                case "ID":
                    Write(session.Stream, "* ID NIL");
                    Write(session.Stream, $"{tag} OK ID completed");
                    break;
                case "LOGIN":
                    HandleLogin(session, cmd, tag);
                    break;
                case "SELECT":
                case "EXAMINE":
                    HandleSelect(session, cmd, tag, name == "EXAMINE");
                    break;
                case "LIST":
                case "LSUB":
                    HandleList(session, cmd, tag);
                    break;
                case "STATUS":
                    HandleStatus(session, cmd, tag);
                    break;
                case "CREATE":
                    HandleCreate(session, cmd, tag);
                    break;
                case "DELETE":
                    HandleDelete(session, cmd, tag);
                    break;
                case "RENAME":
                    Write(session.Stream, $"{tag} NO RENAME not supported");
                    break;
                case "SUBSCRIBE":
                case "UNSUBSCRIBE":
                    Write(session.Stream, $"{tag} OK {name} completed");
                    break;
                case "CLOSE":
                    if (session.Mailbox == null) { Write(session.Stream, $"{tag} BAD CLOSE not valid in this state"); break; }
                    HandleExpunge(session, tag, true);
                    break;
                case "EXPUNGE":
                    if (session.Mailbox == null) { Write(session.Stream, $"{tag} BAD EXPUNGE not valid in this state"); break; }
                    HandleExpunge(session, tag, false);
                    break;
                case "CHECK":
                    if (session.Mailbox == null) { Write(session.Stream, $"{tag} BAD CHECK not valid in this state"); break; }
                    Write(session.Stream, $"{tag} OK CHECK completed");
                    break;
                case "FETCH":
                case "UID FETCH":
                    HandleFetch(session, cmd, tag, name.StartsWith("UID"));
                    break;
                case "STORE":
                case "UID STORE":
                    HandleStore(session, cmd, tag, name.StartsWith("UID"));
                    break;
                case "SEARCH":
                case "UID SEARCH":
                    HandleSearch(session, cmd, tag, name.StartsWith("UID"));
                    break;
                case "COPY":
                case "UID COPY":
                    HandleCopy(session, cmd, tag, name.StartsWith("UID"));
                    break;
                case "APPEND":
                    HandleAppend(session, cmd, tag);
                    break;
                case "STARTTLS":
                    Write(session.Stream, $"{tag} NO TLS not supported");
                    break;
                case "AUTHENTICATE":
                    Write(session.Stream, $"{tag} NO AUTHENTICATE not supported, use LOGIN");
                    break;
                default:
                    Write(session.Stream, $"{tag} BAD Unknown command: {name}");
                    break;
            }
            return true;
        }

        private static void HandleLogin(Session session, ImapCommand cmd, string tag)
        {
            if (session.State != ImapState.NotAuthenticated)
            {
                Write(session.Stream, $"{tag} BAD LOGIN not valid in this state");
                return;
            }
            if (cmd.Args.Count < 2)
            {
                Write(session.Stream, $"{tag} BAD missing arguments to LOGIN");
                return;
            }
            string user = Unquote(cmd.Args[0] as string);
            // 密码不校验（与 POP3 一致，纯本地演示服务）
            string dir = ResolveUserDir(user);
            if (dir == null || !Directory.Exists(Path.Combine("maildb", dir)))
            {
                Write(session.Stream, $"{tag} NO LOGIN failed");
                return;
            }
            session.User = user;
            session.State = ImapState.Authenticated;
            Write(session.Stream, $"{tag} OK LOGIN completed");
        }

        private static void HandleSelect(Session session, ImapCommand cmd, string tag, bool readOnly)
        {
            if (session.State == ImapState.NotAuthenticated)
            {
                Write(session.Stream, $"{tag} BAD not authenticated");
                return;
            }
            string name = cmd.Args.Count > 0 ? Unquote(cmd.Args[0] as string) : "INBOX";
            IMAPMailbox mb = IMAPMailbox.Open(name, session.User);
            if (mb == null)
            {
                Write(session.Stream, $"{tag} NO No such mailbox");
                return;
            }

            session.Mailbox = mb;
            session.ReadOnly = readOnly;

            Write(session.Stream, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
            Write(session.Stream, $"* {mb.Messages.Count} EXISTS");
            Write(session.Stream, "* 0 RECENT");
            Write(session.Stream, $"* OK [UIDVALIDITY {mb.UidValidity}] UIDs valid");
            Write(session.Stream, $"* OK [UIDNEXT {mb.UidNext}] Predicted next UID");
            IMAPMessage firstUnseen = mb.FirstUnseen();
            if (firstUnseen != null)
            {
                Write(session.Stream, $"* OK [UNSEEN {mb.SeqOf(firstUnseen)}] First unseen message");
            }
            if (readOnly)
            {
                Write(session.Stream, $"{tag} OK [READ-ONLY] EXAMINE completed");
            }
            else
            {
                Write(session.Stream, $"{tag} OK [READ-WRITE] SELECT completed");
            }
        }

        private static void HandleList(Session session, ImapCommand cmd, string tag)
        {
            if (session.State == ImapState.NotAuthenticated)
            {
                Write(session.Stream, $"{tag} BAD not authenticated");
                return;
            }
            foreach (string name in IMAPMailbox.ListMailboxes(session.User))
            {
                Write(session.Stream, $"* LIST (\\HasNoChildren) \"/\" \"{EscapeMailbox(name)}\"");
            }
            Write(session.Stream, $"{tag} OK {cmd.Name} completed");
        }

        private static void HandleStatus(Session session, ImapCommand cmd, string tag)
        {
            if (session.State == ImapState.NotAuthenticated)
            {
                Write(session.Stream, $"{tag} BAD not authenticated");
                return;
            }
            string name = cmd.Args.Count > 0 ? Unquote(cmd.Args[0] as string) : "INBOX";
            IMAPMailbox mb = IMAPMailbox.Open(name, session.User);
            if (mb == null)
            {
                Write(session.Stream, $"{tag} NO No such mailbox");
                return;
            }
            string items = string.Join(" ", cmd.Args.Skip(1).Select(a => a as string).Where(s => s != null));
            bool wantMessages = items.Contains("MESSAGES", StringComparison.OrdinalIgnoreCase);
            bool wantRecent = items.Contains("RECENT", StringComparison.OrdinalIgnoreCase);
            bool wantUidNext = items.Contains("UIDNEXT", StringComparison.OrdinalIgnoreCase);
            bool wantUidValidity = items.Contains("UIDVALIDITY", StringComparison.OrdinalIgnoreCase);
            bool wantUnseen = items.Contains("UNSEEN", StringComparison.OrdinalIgnoreCase);

            StringBuilder sb = new StringBuilder($"* STATUS \"{EscapeMailbox(name)}\" (");
            bool first = true;
            void Add(string s) { if (!first) sb.Append(" "); sb.Append(s); first = false; }
            if (wantMessages) Add($"MESSAGES {mb.Messages.Count}");
            if (wantRecent) Add("RECENT 0");
            if (wantUidNext) Add($"UIDNEXT {mb.UidNext}");
            if (wantUidValidity) Add($"UIDVALIDITY {mb.UidValidity}");
            if (wantUnseen) Add($"UNSEEN {mb.UnseenCount()}");
            sb.Append(")");
            Write(session.Stream, sb.ToString());
            Write(session.Stream, $"{tag} OK STATUS completed");
        }

        private static void HandleCreate(Session session, ImapCommand cmd, string tag)
        {
            if (session.State == ImapState.NotAuthenticated) { Write(session.Stream, $"{tag} BAD not authenticated"); return; }
            if (cmd.Args.Count < 1) { Write(session.Stream, $"{tag} BAD missing mailbox name"); return; }
            string name = Unquote(cmd.Args[0] as string);
            string path = IMAPMailbox.MailboxDirPath(name, session.User);
            if (string.IsNullOrEmpty(path) || !IsSafeMailboxPath(path, session.User))
            {
                Write(session.Stream, $"{tag} NO Invalid mailbox name");
                return;
            }
            try
            {
                Directory.CreateDirectory(path);
                Write(session.Stream, $"{tag} OK CREATE completed");
            }
            catch
            {
                Write(session.Stream, $"{tag} NO CREATE failed");
            }
        }

        private static void HandleDelete(Session session, ImapCommand cmd, string tag)
        {
            if (session.State == ImapState.NotAuthenticated) { Write(session.Stream, $"{tag} BAD not authenticated"); return; }
            if (cmd.Args.Count < 1) { Write(session.Stream, $"{tag} BAD missing mailbox name"); return; }
            string name = Unquote(cmd.Args[0] as string);
            if (string.Equals(name, "INBOX", StringComparison.OrdinalIgnoreCase))
            {
                Write(session.Stream, $"{tag} NO Cannot delete INBOX");
                return;
            }
            string path = IMAPMailbox.MailboxDirPath(name, session.User);
            if (string.IsNullOrEmpty(path) || !IsSafeMailboxPath(path, session.User))
            {
                Write(session.Stream, $"{tag} NO Invalid mailbox name");
                return;
            }
            try
            {
                if (!Directory.Exists(path)) { Write(session.Stream, $"{tag} NO No such mailbox"); return; }
                if (Directory.GetFiles(path, "*.eml").Length > 0 || Directory.GetDirectories(path).Length > 0)
                {
                    Write(session.Stream, $"{tag} NO Mailbox not empty");
                    return;
                }
                Directory.Delete(path, true);
                Write(session.Stream, $"{tag} OK DELETE completed");
            }
            catch
            {
                Write(session.Stream, $"{tag} NO DELETE failed");
            }
        }

        private static void HandleAppend(Session session, ImapCommand cmd, string tag)
        {
            if (session.State == ImapState.NotAuthenticated) { Write(session.Stream, $"{tag} BAD not authenticated"); return; }
            if (cmd.Args.Count < 2)
            {
                Write(session.Stream, $"{tag} BAD missing arguments to APPEND");
                return;
            }
            string name = Unquote(cmd.Args[0] as string);
            byte[] data = cmd.Args[cmd.Args.Count - 1] as byte[];
            if (data == null)
            {
                Write(session.Stream, $"{tag} BAD missing literal data");
                return;
            }
            IMAPMailbox mb = IMAPMailbox.Open(name, session.User);
            if (mb == null)
            {
                Write(session.Stream, $"{tag} NO No such mailbox");
                return;
            }
            // 可选标志：(\\Seen) 之类，位于 mailbox 与 date/literal 之间
            List<string> flags = new List<string>();
            foreach (object a in cmd.Args.Skip(1).Take(cmd.Args.Count - 2))
            {
                string s = a as string;
                if (s != null && s.StartsWith("("))
                {
                    Match m = Regex.Match(s, @"\(([^)]*)\)");
                    if (m.Success)
                    {
                        foreach (string f in m.Groups[1].Value.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            flags.Add(f);
                        }
                    }
                }
            }
            IMAPMessage msg = mb.AppendMessage(data, flags);
            Write(session.Stream, $"{tag} OK [APPENDUID {mb.UidValidity} {msg.Uid}] APPEND completed");
        }

        #endregion

        #region 消息集与 FETCH

        private static long StarValue(string token, IMAPMailbox mb, bool uidMode)
        {
            if (token == "*")
            {
                if (mb.Messages.Count == 0) return 0;
                return uidMode ? mb.Messages.Max(m => m.Uid) : mb.Messages.Count;
            }
            return long.Parse(token);
        }

        private static List<IMAPMessage> ResolveSet(string set, IMAPMailbox mb, bool uidMode)
        {
            List<IMAPMessage> result = new List<IMAPMessage>();
            if (set == null) return result;
            foreach (string token in set.Split(','))
            {
                string t = token.Trim();
                if (t.Length == 0) continue;
                int colon = t.IndexOf(':');
                if (colon >= 0)
                {
                    long a = StarValue(t.Substring(0, colon).Trim(), mb, uidMode);
                    long b = StarValue(t.Substring(colon + 1).Trim(), mb, uidMode);
                    if (b < a) { long tmp = a; a = b; b = tmp; }
                    for (long v = a; v <= b; v++)
                    {
                        IMAPMessage m = FindByValue(mb, v, uidMode);
                        if (m != null && !result.Contains(m)) result.Add(m);
                    }
                }
                else
                {
                    IMAPMessage m = FindByValue(mb, StarValue(t, mb, uidMode), uidMode);
                    if (m != null && !result.Contains(m)) result.Add(m);
                }
            }
            result.Sort((x, y) => mb.SeqOf(x).CompareTo(mb.SeqOf(y)));
            return result;
        }

        private static IMAPMessage FindByValue(IMAPMailbox mb, long v, bool uidMode)
        {
            return mb.Messages.FirstOrDefault(m => uidMode ? m.Uid == v : mb.SeqOf(m) == v);
        }

        private static void HandleFetch(Session session, ImapCommand cmd, string tag, bool uidMode)
        {
            if (session.Mailbox == null) { Write(session.Stream, $"{tag} BAD {cmd.Name} not valid in this state"); return; }
            if (cmd.Args.Count < 2) { Write(session.Stream, $"{tag} BAD missing arguments to FETCH"); return; }

            IMAPMailbox mb = session.Mailbox;
            string set = cmd.Args[0] as string;
            string itemSpec = string.Join(" ", cmd.Args.Skip(1).Select(a => a as string).Where(s => s != null));

            List<IMAPMessage> msgs = ResolveSet(set, mb, uidMode);
            List<string> items = ParseFetchItems(itemSpec);

            foreach (IMAPMessage m in msgs)
            {
                WriteFetchResponse(session.Stream, mb.SeqOf(m), m, items);
            }
            Write(session.Stream, $"{tag} OK {cmd.Name} completed");
        }

        private static List<string> ParseFetchItems(string spec)
        {
            List<string> items = new List<string>();
            spec = spec.Trim();
            if (spec.StartsWith("("))
            {
                int depth = 0;
                int bracket = 0;
                StringBuilder cur = new StringBuilder();
                foreach (char c in spec)
                {
                    if (c == '[') { bracket++; cur.Append(c); }
                    else if (c == ']') { bracket--; cur.Append(c); }
                    else if (c == '(') { depth++; if (depth > 1) cur.Append(c); }
                    else if (c == ')') { depth--; if (depth == 0) break; cur.Append(c); }
                    else if (c == ' ' && depth == 1 && bracket == 0)
                    {
                        if (cur.Length > 0) { items.Add(cur.ToString()); cur.Clear(); }
                    }
                    else cur.Append(c);
                }
                if (cur.Length > 0) items.Add(cur.ToString());
            }
            else
            {
                items.Add(spec);
            }

            List<string> expanded = new List<string>();
            foreach (string it in items)
            {
                switch (it.ToUpperInvariant())
                {
                    case "ALL":
                        expanded.AddRange(new[] { "FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE" });
                        break;
                    case "FAST":
                        expanded.AddRange(new[] { "FLAGS", "INTERNALDATE", "RFC822.SIZE" });
                        break;
                    case "FULL":
                        expanded.AddRange(new[] { "FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY" });
                        break;
                    default:
                        expanded.Add(it);
                        break;
                }
            }
            return expanded;
        }
private static void WriteFetchResponse(NetworkStream stream, int seq, IMAPMessage msg, List<string> items)
        {
            byte[] raw = msg.GetRaw();
            WriteRaw(stream, Encoding.UTF8.GetBytes($"* {seq} FETCH ("));
            bool first = true;

            foreach (string item in items)
            {
                string upper = item.ToUpperInvariant();
                string name = item;
                if (name.StartsWith("BODY.PEEK", StringComparison.OrdinalIgnoreCase))
                {
                    name = "BODY" + name.Substring("BODY.PEEK".Length);
                }

                string value = null;
                byte[] literal = null;

                if (upper == "UID") value = msg.Uid.ToString();
                else if (upper == "FLAGS") value = FormatFlags(msg.Flags);
                else if (upper == "RFC822.SIZE") value = msg.Size.ToString();
                else if (upper == "INTERNALDATE") value = FormatInternalDate(msg);
                else if (upper == "ENVELOPE") value = BuildEnvelope(raw);
                else if (upper == "BODYSTRUCTURE") value = BuildBodyStructure(raw);
                else if (upper == "RFC822" || upper == "BODY[]" || upper == "BODY[0]")
                {
                    literal = ApplyPartial(raw, item);
                    name = CleanPartialName(name);
                }
                else if (upper == "RFC822.HEADER" || upper == "BODY[HEADER]")
                {
                    literal = ApplyPartial(SplitHeaderText(raw).Header, item);
                    name = CleanPartialName(name);
                }
                else if (upper == "RFC822.TEXT" || upper == "BODY[TEXT]")
                {
                    literal = ApplyPartial(SplitHeaderText(raw).Text, item);
                    name = CleanPartialName(name);
                }
                else if (upper.StartsWith("BODY[HEADER.FIELDS"))
                {
                    literal = BuildHeaderFields(raw, item);
                }
                else if (upper.StartsWith("BODY[") || upper.StartsWith("BODY.PEEK["))
                {
                    literal = ResolveBodySection(raw, item);
                    name = CleanPartialName(name);
                }
                else
                {
                    continue; // 不支持的项跳过
                }

                if (!first) WriteRaw(stream, Encoding.UTF8.GetBytes(" "));
                if (literal != null)
                {
                    WriteRaw(stream, Encoding.UTF8.GetBytes($"{name} {{{literal.Length}}}\r\n"));
                    WriteRaw(stream, literal);
                    WriteRaw(stream, Encoding.UTF8.GetBytes("\r\n"));
                }
                else
                {
                    WriteRaw(stream, Encoding.UTF8.GetBytes($"{name} {value}"));
                }
                first = false;
            }
            WriteRaw(stream, Encoding.UTF8.GetBytes(")\r\n"));
        }

        // 去掉 BODY[..]<offset.count> 的 <..> 部分，用于响应中的名称
        private static string CleanPartialName(string name)
        {
            int lt = name.LastIndexOf('<');
            if (lt >= 0) name = name.Substring(0, lt);
            return name;
        }

        private static byte[] ApplyPartial(byte[] data, string item)
        {
            int lt = item.LastIndexOf('<');
            if (lt >= 0)
            {
                int gt = item.IndexOf('>', lt);
                if (gt > lt)
                {
                    string inner = item.Substring(lt + 1, gt - lt - 1);
                    string[] parts = inner.Split('.');
                    if (parts.Length == 2 && int.TryParse(parts[0], out int off) && int.TryParse(parts[1], out int cnt))
                    {
                        if (off >= data.Length) return new byte[0];
                        int len = Math.Min(cnt, data.Length - off);
                        return data.Skip(off).Take(len).ToArray();
                    }
                }
            }
            return data;
        }

        private static (byte[] Header, byte[] Text) SplitHeaderText(byte[] raw)
        {
            for (int i = 0; i + 3 < raw.Length; i++)
            {
                if (raw[i] == 13 && raw[i + 1] == 10 && raw[i + 2] == 13 && raw[i + 3] == 10)
                {
                    return (raw.Take(i).ToArray(), raw.Skip(i + 4).ToArray());
                }
            }
            for (int i = 0; i + 1 < raw.Length; i++)
            {
                if (raw[i] == 10 && raw[i + 1] == 10)
                {
                    return (raw.Take(i + 1).ToArray(), raw.Skip(i + 2).ToArray());
                }
            }
            return (raw, new byte[0]);
        }

        private static byte[] BuildHeaderFields(byte[] raw, string item)
        {
            Match m = Regex.Match(item, @"HEADER\.FIELDS\s*\((.*?)\)", RegexOptions.IgnoreCase);
            HashSet<string> wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (m.Success)
            {
                foreach (string f in m.Groups[1].Value.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    wanted.Add(f);
                }
            }
            byte[] header = SplitHeaderText(raw).Header;
            string text = Encoding.UTF8.GetString(header);
            StringBuilder sb = new StringBuilder();
            bool keepContinuation = false;
            foreach (string line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                if (line.Length == 0) break;
                int colon = line.IndexOf(':');
                if (colon > 0)
                {
                    string fn = line.Substring(0, colon).Trim();
                    keepContinuation = wanted.Contains(fn);
                    if (keepContinuation) sb.Append(line).Append("\r\n");
                }
                else if (keepContinuation && (line[0] == ' ' || line[0] == '\t'))
                {
                    sb.Append(line).Append("\r\n");
                }
            }
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        // 解析 BODY[section] 等节
        private static byte[] ResolveBodySection(byte[] raw, string item)
        {
            int open = item.IndexOf('[');
            int close = item.IndexOf(']', open);
            if (open < 0 || close < 0) return new byte[0];
            string section = item.Substring(open + 1, close - open - 1).Trim();
            string upper = section.ToUpperInvariant();

            byte[] result;
            if (upper.Length == 0 || upper == "0") result = raw;
            else if (upper == "HEADER") result = SplitHeaderText(raw).Header;
            else if (upper == "TEXT") result = SplitHeaderText(raw).Text;
            else if (upper.StartsWith("HEADER.FIELDS")) result = BuildHeaderFields(raw, item);
            else if (upper == "MIME") result = new byte[0];
            else result = ExtractPart(raw, section);

            return ApplyPartial(result, item);
        }

        private static byte[] ExtractPart(byte[] raw, string section)
        {
            try
            {
                MimeMessage m = MimeMessage.Load(new MemoryStream(raw));
                string[] segs = section.Split('.');
                MimeEntity entity = m.Body;
                string suffix = null;

                foreach (string seg in segs)
                {
                    string su = seg.ToUpperInvariant();
                    if (su == "TEXT" || su == "MIME" || su == "HEADER")
                    {
                        suffix = su;
                        break;
                    }
                    if (int.TryParse(seg, out int idx) && entity is Multipart mp)
                    {
                        if (idx >= 1 && idx <= mp.Count) entity = mp[idx - 1];
                        else return new byte[0];
                    }
                    else
                    {
                        return new byte[0];
                    }
                }

                using (MemoryStream ms = new MemoryStream())
                {
                    if (entity is MimePart part)
                    {
                        part.WriteTo(ms);
                        byte[] full = ms.ToArray();
                        if (suffix == "HEADER") return SplitHeaderText(full).Header;
                        if (suffix == "TEXT") return SplitHeaderText(full).Text;
                        return full;
                    }
                }
                return new byte[0];
            }
            catch
            {
                return new byte[0];
            }
        }

        #endregion

        #region ENVELOPE / BODYSTRUCTURE

        private static string BuildEnvelope(byte[] raw)
        {
            try
            {
                MimeMessage m = MimeMessage.Load(new MemoryStream(raw));
                string date = NString(GetHeaderValue(m, "Date"));
                string subject = NString(m.Subject);
                string from = BuildAddressList(m.From);
                InternetAddressList senderList = m.Sender != null ? new InternetAddressList { m.Sender } : m.From;
                string sender = BuildAddressList(senderList);
                string replyTo = BuildAddressList(m.ReplyTo.Count > 0 ? m.ReplyTo : m.From);
                string to = BuildAddressList(m.To);
                string cc = BuildAddressList(m.Cc);
                string bcc = BuildAddressList(m.Bcc);
                string inReplyTo = NString(GetHeaderValue(m, "In-Reply-To"));
                string msgId = NString(GetHeaderValue(m, "Message-Id"));
                return $"({date} {subject} {from} {sender} {replyTo} {to} {cc} {bcc} {inReplyTo} {msgId})";
            }
            catch
            {
                return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
            }
        }

        private static string BuildAddressList(InternetAddressList list)
        {
            if (list == null || list.Count == 0) return "NIL";
            StringBuilder sb = new StringBuilder("(");
            bool first = true;
            foreach (InternetAddress addr in list)
            {
                if (!first) sb.Append(" ");
                first = false;
                if (addr is MailboxAddress mbx)
                {
                    string address = mbx.Address ?? "";
                    int at = address.IndexOf('@');
                    string local = at >= 0 ? address.Substring(0, at) : address;
                    string domain = at >= 0 ? address.Substring(at + 1) : null;
                    sb.Append($"({NString(mbx.Name)} NIL {NString(local)} {NString(domain)})");
                }
                else if (addr is GroupAddress grp)
                {
                    sb.Append($"({NString(grp.Name)} NIL NIL NIL)");
                }
                else
                {
                    sb.Append("(NIL NIL NIL NIL)");
                }
            }
            sb.Append(")");
            return sb.ToString();
        }

        private static string BuildBodyStructure(byte[] raw)
        {
            try
            {
                MimeMessage m = MimeMessage.Load(new MemoryStream(raw));
                return BuildEntityStructure(m.Body);
            }
            catch
            {
                return "(NIL)";
            }
        }

        private static string BuildEntityStructure(MimeEntity entity)
        {
            if (entity is Multipart mp)
            {
                List<string> parts = new List<string>();
                foreach (MimeEntity sub in mp) parts.Add(BuildEntityStructure(sub));
                string subtype = (mp.ContentType.MediaSubtype ?? "mixed").ToLowerInvariant();
                string ps = BuildContentTypeParams(mp.ContentType);
                return $"({string.Join(" ", parts)} \"{subtype}\" {ps} NIL NIL NIL)";
            }
            if (entity is MimePart p)
            {
                string type = (p.ContentType.MediaType ?? "text").ToLowerInvariant();
                string subtype = (p.ContentType.MediaSubtype ?? "plain").ToLowerInvariant();
                string ps = BuildContentTypeParams(p.ContentType);
                string id = NString(p.ContentId);
                string enc = EncodingName(p.ContentTransferEncoding);
                long size = 0;
                try { if (p.Content != null) size = p.Content.Stream.Length; } catch { }
                if (type == "text")
                {
                    int lines = 0;
                    try { lines = CountLines(p.Content.Stream); } catch { }
                    return $"(\"{type}\" \"{subtype}\" {ps} {id} NIL \"{enc}\" {size} {lines} NIL NIL NIL)";
                }
                return $"(\"{type}\" \"{subtype}\" {ps} {id} NIL \"{enc}\" {size} NIL NIL NIL)";
            }
            return "(NIL)";
        }

        private static string BuildContentTypeParams(ContentType ct)
        {
            if (ct.Parameters == null || ct.Parameters.Count == 0) return "NIL";
            StringBuilder sb = new StringBuilder("(");
            bool first = true;
            foreach (Parameter prm in ct.Parameters)
            {
                if (!first) sb.Append(" ");
                first = false;
                sb.Append(NString(prm.Name)).Append(" ").Append(NString(prm.Value));
            }
            sb.Append(")");
            return sb.ToString();
        }

        private static string EncodingName(ContentEncoding enc)
        {
            switch (enc)
            {
                case ContentEncoding.EightBit: return "8bit";
                case ContentEncoding.Binary: return "binary";
                case ContentEncoding.Base64: return "base64";
                case ContentEncoding.QuotedPrintable: return "quoted-printable";
                default: return "7bit";
            }
        }

        private static int CountLines(Stream s)
        {
            try
            {
                if (!s.CanSeek) return 0;
                s.Position = 0;
                int lines = 0;
                int b;
                int prev = -1;
                while ((b = s.ReadByte()) != -1)
                {
                    if (b == '\n') lines++;
                    prev = b;
                }
                if (prev != -1 && prev != '\n') lines++;
                return lines;
            }
            catch
            {
                return 0;
            }
        }

        #endregion

        #region STORE / SEARCH / COPY / EXPUNGE

        private static void HandleStore(Session session, ImapCommand cmd, string tag, bool uidMode)
        {
            if (session.Mailbox == null) { Write(session.Stream, $"{tag} BAD {cmd.Name} not valid in this state"); return; }
            if (session.ReadOnly) { Write(session.Stream, $"{tag} NO [READ-ONLY] mailbox is read-only"); return; }
            if (cmd.Args.Count < 3) { Write(session.Stream, $"{tag} BAD missing arguments to STORE"); return; }

            IMAPMailbox mb = session.Mailbox;
            string set = cmd.Args[0] as string;
            string op = (cmd.Args[1] as string ?? "").ToUpperInvariant();
            string flagSpec = string.Join(" ", cmd.Args.Skip(2).Select(a => a as string).Where(s => s != null));

            bool silent = op.Contains(".SILENT");
            op = op.Replace(".SILENT", "");

            List<string> newFlags = new List<string>();
            Match m = Regex.Match(flagSpec, @"\(([^)]*)\)");
            string inside = m.Success ? m.Groups[1].Value : flagSpec;
            foreach (string f in inside.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                newFlags.Add(f);
            }
            // 过滤系统标志：仅保留已知标志
            string[] allowed = { "\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft" };
            newFlags = newFlags.Where(f => allowed.Contains(f, StringComparer.OrdinalIgnoreCase)).ToList();

            List<IMAPMessage> msgs = ResolveSet(set, mb, uidMode);
            foreach (IMAPMessage msg in msgs)
            {
                switch (op)
                {
                    case "+FLAGS":
                        foreach (string f in newFlags) if (!msg.Flags.Contains(f, StringComparer.OrdinalIgnoreCase)) msg.Flags.Add(f);
                        break;
                    case "-FLAGS":
                        msg.Flags.RemoveAll(f => newFlags.Contains(f, StringComparer.OrdinalIgnoreCase));
                        break;
                    case "FLAGS":
                        msg.Flags = new List<string>(newFlags);
                        break;
                    default:
                        Write(session.Stream, $"{tag} BAD unknown STORE operation");
                        return;
                }
                if (!silent)
                {
                    Write(session.Stream, $"* {mb.SeqOf(msg)} FETCH (FLAGS {FormatFlags(msg.Flags)})");
                }
            }
            mb.SaveFlags();
            Write(session.Stream, $"{tag} OK {cmd.Name} completed");
        }

        private static void HandleExpunge(Session session, string tag, bool isClose)
        {
            if (session.ReadOnly)
            {
                Write(session.Stream, $"{tag} NO [READ-ONLY] mailbox is read-only");
                return;
            }
            IMAPMailbox mb = session.Mailbox;
            List<IMAPMessage> toDelete = mb.Messages.Where(m => m.Flags.Contains("\\Deleted")).OrderByDescending(m => mb.SeqOf(m)).ToList();
            foreach (IMAPMessage m in toDelete)
            {
                int seq = mb.SeqOf(m);
                mb.DeleteMessage(m);
                Write(session.Stream, $"* {seq} EXPUNGE");
            }
            if (isClose)
            {
                session.Mailbox = null;
                session.ReadOnly = false;
                session.State = ImapState.Authenticated;
                Write(session.Stream, $"{tag} OK CLOSE completed");
            }
            else
            {
                Write(session.Stream, $"{tag} OK EXPUNGE completed");
            }
        }

        private static void HandleSearch(Session session, ImapCommand cmd, string tag, bool uidMode)
        {
            if (session.Mailbox == null) { Write(session.Stream, $"{tag} BAD {cmd.Name} not valid in this state"); return; }
            IMAPMailbox mb = session.Mailbox;
            string criteria = string.Join(" ", cmd.Args.Select(a => a as string).Where(s => s != null));

            List<IMAPMessage> matches = new List<IMAPMessage>();
            if (string.IsNullOrWhiteSpace(criteria))
            {
                matches.AddRange(mb.Messages);
            }
            else
            {
                List<string> toks = TokenizeSearch(criteria);
                foreach (IMAPMessage msg in mb.Messages)
                {
                    int pos = 0;
                    bool ok = true;
                    while (pos < toks.Count)
                    {
                        if (!MatchSearch(mb, msg, toks, ref pos)) { ok = false; break; }
                    }
                    if (ok) matches.Add(msg);
                }
            }

            List<long> values = matches.Select(m => uidMode ? m.Uid : (long)mb.SeqOf(m)).ToList();
            Write(session.Stream, "* SEARCH " + string.Join(" ", values));
            Write(session.Stream, $"{tag} OK {cmd.Name} completed");
        }

        private static List<string> TokenizeSearch(string s)
        {
            List<string> tokens = new List<string>();
            int i = 0;
            while (i < s.Length)
            {
                if (char.IsWhiteSpace(s[i])) { i++; continue; }
                if (s[i] == '(')
                {
                    int depth = 0;
                    StringBuilder sb = new StringBuilder();
                    while (i < s.Length)
                    {
                        char c = s[i];
                        if (c == '(') depth++;
                        else if (c == ')')
                        {
                            depth--;
                            if (depth == 0) { i++; break; }
                        }
                        sb.Append(c);
                        i++;
                    }
                    tokens.Add(sb.ToString());
                    continue;
                }
                if (s[i] == '"')
                {
                    int j = i + 1;
                    StringBuilder sb = new StringBuilder();
                    while (j < s.Length)
                    {
                        char c = s[j];
                        if (c == '\\' && j + 1 < s.Length) { sb.Append(s[j + 1]); j += 2; continue; }
                        if (c == '"') break;
                        sb.Append(c);
                        j++;
                    }
                    i = Math.Min(j + 1, s.Length);
                    tokens.Add(sb.ToString());
                    continue;
                }
                int k = i;
                while (k < s.Length && !char.IsWhiteSpace(s[k]) && s[k] != '(' && s[k] != ')') k++;
                tokens.Add(s.Substring(i, k - i));
                i = k;
            }
            return tokens;
        }

        private static bool MatchSearch(IMAPMailbox mb, IMAPMessage msg, List<string> toks, ref int pos)
        {
            string t = toks[pos].ToUpperInvariant();
            switch (t)
            {
                case "ALL": pos++; return true;
                case "UNSEEN": pos++; return !msg.Flags.Contains("\\Seen");
                case "SEEN": pos++; return msg.Flags.Contains("\\Seen");
                case "FLAGGED": pos++; return msg.Flags.Contains("\\Flagged");
                case "UNFLAGGED": pos++; return !msg.Flags.Contains("\\Flagged");
                case "DELETED": pos++; return msg.Flags.Contains("\\Deleted");
                case "UNDELETED": pos++; return !msg.Flags.Contains("\\Deleted");
                case "ANSWERED": pos++; return msg.Flags.Contains("\\Answered");
                case "UNANSWERED": pos++; return !msg.Flags.Contains("\\Answered");
                case "DRAFT": pos++; return msg.Flags.Contains("\\Draft");
                case "UNDRAFT": pos++; return !msg.Flags.Contains("\\Draft");
                case "NEW": pos++; return !msg.Flags.Contains("\\Seen");
                case "OLD": pos++; return true;
                case "RECENT": pos++; return false;
                case "FROM": case "TO": case "CC": case "BCC":
                    {
                        string key = t; pos++;
                        string val = toks[pos].ToLowerInvariant(); pos++;
                        return HeaderContains(msg, key, val);
                    }
                case "SUBJECT":
                    {
                        pos++;
                        string val = toks[pos].ToLowerInvariant(); pos++;
                        try
                        {
                            MimeMessage m = MimeMessage.Load(new MemoryStream(msg.GetRaw()));
                            return (m.Subject ?? "").ToLowerInvariant().Contains(val);
                        }
                        catch { return false; }
                    }
                case "BODY": case "TEXT":
                    {
                        pos++;
                        string val = toks[pos].ToLowerInvariant(); pos++;
                        return DecodeRaw(msg.GetRaw()).ToLowerInvariant().Contains(val);
                    }
                case "HEADER":
                    {
                        pos++;
                        string fname = toks[pos].ToLowerInvariant(); pos++;
                        string fval = toks[pos].ToLowerInvariant(); pos++;
                        return HeaderContains(msg, fname, fval);
                    }
                case "UID":
                    {
                        pos++;
                        string set = toks[pos]; pos++;
                        return ResolveSet(set, mb, true).Contains(msg);
                    }
                case "NOT":
                    {
                        pos++;
                        return !MatchSearch(mb, msg, toks, ref pos);
                    }
                case "OR":
                    {
                        pos++;
                        bool a = MatchSearch(mb, msg, toks, ref pos);
                        bool b = MatchSearch(mb, msg, toks, ref pos);
                        return a || b;
                    }
                default:
                    if (t.StartsWith("(") && t.EndsWith(")") && t.Length > 2)
                    {
                        pos++;
                        List<string> inner = TokenizeSearch(t.Substring(1, t.Length - 2));
                        int ip = 0;
                        while (ip < inner.Count)
                        {
                            if (!MatchSearch(mb, msg, inner, ref ip)) return false;
                        }
                        return true;
                    }
                    if (t == "SMALLER" || t == "LARGER" || t == "ON" || t == "BEFORE" || t == "SINCE")
                    {
                        pos += 2; // 未实现的日期/大小条件，宽松处理为匹配
                        return true;
                    }
                    pos++;
                    return true;
            }
        }

        private static string DecodeRaw(byte[] raw)
        {
            try { return Encoding.UTF8.GetString(raw); }
            catch { return Encoding.Latin1.GetString(raw); }
        }

        private static string GetHeaderValue(MimeMessage m, string field)
        {
            foreach (Header h in m.Headers)
            {
                if (string.Equals(h.Field, field, StringComparison.OrdinalIgnoreCase))
                    return h.Value;
            }
            return null;
        }

        private static bool HeaderContains(IMAPMessage msg, string field, string value)
        {
            try
            {
                MimeMessage m = MimeMessage.Load(new MemoryStream(msg.GetRaw()));
                string v = GetHeaderValue(m, field);
                return v != null && v.ToLowerInvariant().Contains(value);
            }
            catch
            {
                return false;
            }
        }

        private static void HandleCopy(Session session, ImapCommand cmd, string tag, bool uidMode)
        {
            if (session.Mailbox == null) { Write(session.Stream, $"{tag} BAD {cmd.Name} not valid in this state"); return; }
            if (cmd.Args.Count < 2) { Write(session.Stream, $"{tag} BAD missing arguments to COPY"); return; }
            IMAPMailbox src = session.Mailbox;
            string set = cmd.Args[0] as string;
            string destName = Unquote(cmd.Args[1] as string);
            IMAPMailbox dest = IMAPMailbox.Open(destName, session.User);
            if (dest == null)
            {
                Write(session.Stream, $"{tag} NO No such mailbox: {destName}");
                return;
            }
            foreach (IMAPMessage m in ResolveSet(set, src, uidMode))
            {
                dest.AppendMessage(m.GetRaw(), new List<string>(m.Flags));
            }
            Write(session.Stream, $"{tag} OK {cmd.Name} completed");
        }

        #endregion

        #region 工具

        private static string ResolveUserDir(string user)
        {
            if (string.IsNullOrEmpty(user)) return null;
            if (user.Contains("@"))
            {
                string d = POP3Service.MailBoxesToDirName(user);
                if (d == null || d.Contains("..") || d.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                    d.Contains('/') || d.Contains('\\'))
                {
                    return null;
                }
                return d;
            }
            // 无 @：尝试在 maildb 下找唯一的 {user}_* 目录
            string root = Path.Combine("maildb");
            if (!Directory.Exists(root)) return null;
            List<string> matches = Directory.GetDirectories(root)
                .Select(Path.GetFileName)
                .Where(n => n != null && n.StartsWith(user + "_", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (matches.Count == 1) return matches[0];
            return null;
        }

        private static bool IsSafeMailboxPath(string path, string user)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string home = IMAPMailbox.HomeDirPath(user);
            string full = Path.GetFullPath(path);
            string homeFull = Path.GetFullPath(home);
            return full.StartsWith(homeFull + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
                   !full.EndsWith(".imap_meta.json") && !full.EndsWith(".imap_flags.json");
        }

        private static string FormatFlags(List<string> flags)
        {
            if (flags.Count == 0) return "()";
            return "(" + string.Join(" ", flags) + ")";
        }

        private static string FormatInternalDate(IMAPMessage msg)
        {
            DateTime dt = File.GetLastWriteTimeUtc(msg.FilePath);
            return "\"" + dt.ToString("dd-MMM-yyyy HH:mm:ss", CultureInfo.InvariantCulture) + " +0000\"";
        }

        private static string NString(string s)
        {
            if (string.IsNullOrEmpty(s)) return "NIL";
            return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        }

        private static string EscapeMailbox(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        private static void Write(NetworkStream stream, string line)
        {
            byte[] data = Encoding.UTF8.GetBytes(line + "\r\n");
            stream.Write(data, 0, data.Length);
            stream.Flush();
        }

        private static void WriteRaw(NetworkStream stream, byte[] data)
        {
            stream.Write(data, 0, data.Length);
            stream.Flush();
        }

        #endregion
    }
}
