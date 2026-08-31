using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;

namespace YukiDNS.MAIL_CORE
{
    // 定义POP3会话的状态
    public enum POP3State
    {
        Authorization, // 授权状态，等待 USER/PASS
        Transaction,   // 事务状态，处理邮件相关命令
        Update         // 更新状态，处理 QUIT
    }

    public class POP3Service
    {
        // 邮件根目录
        private const string MailboxRootPath = @"maildb";

        public static void Start()
        {
            Thread pop3 = new Thread(POP3_THREAD_TCP);
            pop3.IsBackground = true;
            pop3.Start();
            Console.WriteLine("POP3Service started, listening on port 110...");
        }

        private static void POP3_THREAD_TCP()
        {
            int port = 110;
            TcpListener server = null;
            try
            {
                server = new TcpListener(IPAddress.Any, port);
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

        private static void HandleClient(TcpClient client)
        {
            POP3State state = POP3State.Authorization;
            string currentUser = null;

            // 登录成功后加载的邮件数据（原始字节，保留 UTF-8 内容）
            List<byte[]> mailbox = new List<byte[]>();
            List<string> uidlList = new List<string>();
            List<bool> deletedMessages = new List<bool>();

            try
            {
                NetworkStream stream = client.GetStream();
                SendLine(stream, "+OK POP3 server ready");

                string command;
                while ((command = ReadLine(stream)) != null)
                {
                    string[] parts = command.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 0) continue;
                    string cmd = parts[0].ToUpperInvariant();

                    if (cmd == "PASS")
                    {
                        Console.WriteLine("Received: PASS ********");
                    }
                    else
                    {
                        Console.WriteLine("Received: {0}", command);
                    }

                    switch (state)
                    {
                        case POP3State.Authorization:
                            HandleAuthorizationState(stream, cmd, parts, ref currentUser, ref state, ref mailbox, ref uidlList, ref deletedMessages);
                            break;
                        case POP3State.Transaction:
                            HandleTransactionState(stream, cmd, parts, ref state, currentUser, mailbox, uidlList, deletedMessages);
                            break;
                        case POP3State.Update:
                            SendLine(stream, "-ERR Invalid state for this command");
                            break;
                    }

                    if (cmd == "QUIT" && state == POP3State.Update)
                    {
                        break;
                    }
                }
            }
            catch (IOException e)
            {
                Console.WriteLine("IOException: {0}", e);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e);
            }
            finally
            {
                client.Close();
                Console.WriteLine("Connection closed.");
            }
        }

        private static void HandleAuthorizationState(NetworkStream stream, string cmd, string[] parts, ref string currentUser, ref POP3State state, ref List<byte[]> mailbox, ref List<string> uidlList, ref List<bool> deletedMessages)
        {
            switch (cmd)
            {
                case "CAPA":
                    SendLine(stream, "+OK Capability list follows");
                    SendLine(stream, "USER");
                    SendLine(stream, "UIDL");
                    SendLine(stream, "TOP");
                    SendLine(stream, "IMPLEMENTATION YukiDNS-POP3");
                    SendLine(stream, ".");
                    break;
                case "USER":
                    if (parts.Length > 1)
                    {
                        string dirName = MailBoxesToDirName(parts[1]);
                        string userMailboxPath = Path.Combine(MailboxRootPath, dirName ?? "");

                        if (IsValidDirName(dirName) && Directory.Exists(userMailboxPath))
                        {
                            currentUser = parts[1];
                            SendLine(stream, $"+OK User {parts[1]} accepted. Please send PASS command.");
                        }
                        else
                        {
                            SendLine(stream, "-ERR User does not exist.");
                        }
                    }
                    else
                    {
                        SendLine(stream, "-ERR Missing username.");
                    }
                    break;
                case "PASS":
                    if (currentUser != null && parts.Length > 1)
                    {
                        SendLine(stream, "+OK Logged in successfully.");

                        string mailboxDir = MailBoxesToDirName(currentUser);
                        LoadMailboxForUser(mailboxDir, out mailbox, out uidlList);
                        deletedMessages = mailbox.Select(_ => false).ToList();

                        state = POP3State.Transaction; // 成功后进入事务状态
                    }
                    else
                    {
                        SendLine(stream, "-ERR Invalid command sequence or missing password.");
                    }
                    break;
                case "NOOP":
                    SendLine(stream, "+OK");
                    break;
                case "QUIT":
                    SendLine(stream, "+OK Goodbye");
                    state = POP3State.Update; // 进入更新状态，等待连接关闭
                    break;
                default:
                    SendLine(stream, "-ERR Invalid command in Authorization state.");
                    break;
            }
        }

        private static void HandleTransactionState(NetworkStream stream, string cmd, string[] parts, ref POP3State state, string currentUser, List<byte[]> mailbox, List<string> uidlList, List<bool> deletedMessages)
        {
            switch (cmd)
            {
                case "STAT":
                    {
                        int count = 0;
                        long total = 0;
                        for (int i = 0; i < mailbox.Count; i++)
                        {
                            if (!deletedMessages[i])
                            {
                                count++;
                                total += PrepareMessageBytes(mailbox[i]).Length;
                            }
                        }
                        SendLine(stream, $"+OK {count} {total}");
                    }
                    break;
                case "LIST":
                    if (parts.Length > 1)
                    {
                        // LIST msg：单条消息
                        if (int.TryParse(parts[1], out int n) && n > 0 && n <= mailbox.Count && !deletedMessages[n - 1])
                        {
                            SendLine(stream, $"+OK {n} {PrepareMessageBytes(mailbox[n - 1]).Length}");
                        }
                        else
                        {
                            SendLine(stream, "-ERR No such message.");
                        }
                    }
                    else
                    {
                        SendLine(stream, "+OK Scan listing follows");
                        for (int i = 0; i < mailbox.Count; i++)
                        {
                            if (!deletedMessages[i])
                            {
                                SendLine(stream, $"{i + 1} {PrepareMessageBytes(mailbox[i]).Length}");
                            }
                        }
                        SendLine(stream, ".");
                    }
                    break;
                case "RETR":
                    if (parts.Length > 1)
                    {
                        if (int.TryParse(parts[1], out int messageNumber) && messageNumber > 0 && messageNumber <= mailbox.Count && !deletedMessages[messageNumber - 1])
                        {
                            byte[] transfer = PrepareMessageBytes(mailbox[messageNumber - 1]);
                            SendLine(stream, $"+OK {transfer.Length} octets");
                            stream.Write(transfer, 0, transfer.Length);
                            SendLine(stream, ".");
                        }
                        else
                        {
                            SendLine(stream, "-ERR No such message.");
                        }
                    }
                    else
                    {
                        SendLine(stream, "-ERR Missing message number.");
                    }
                    break;
                case "TOP":
                    if (parts.Length > 2)
                    {
                        if (int.TryParse(parts[1], out int messageNumber) && int.TryParse(parts[2], out int lineCount) &&
                            lineCount >= 0 && messageNumber > 0 && messageNumber <= mailbox.Count && !deletedMessages[messageNumber - 1])
                        {
                            byte[] transfer = PrepareTopBytes(mailbox[messageNumber - 1], lineCount);
                            SendLine(stream, $"+OK Top of message follows");
                            stream.Write(transfer, 0, transfer.Length);
                            SendLine(stream, ".");
                        }
                        else
                        {
                            SendLine(stream, "-ERR No such message.");
                        }
                    }
                    else
                    {
                        SendLine(stream, "-ERR Missing message number and line count.");
                    }
                    break;
                case "UIDL":
                    if (parts.Length > 1)
                    {
                        if (int.TryParse(parts[1], out int messageNumber) && messageNumber > 0 && messageNumber <= uidlList.Count && !deletedMessages[messageNumber - 1])
                        {
                            SendLine(stream, $"+OK {messageNumber} {uidlList[messageNumber - 1]}");
                        }
                        else
                        {
                            SendLine(stream, "-ERR No such message.");
                        }
                    }
                    else
                    {
                        SendLine(stream, "+OK UIDL listing follows");
                        for (int i = 0; i < uidlList.Count; i++)
                        {
                            if (!deletedMessages[i])
                            {
                                SendLine(stream, $"{i + 1} {uidlList[i]}");
                            }
                        }
                        SendLine(stream, ".");
                    }
                    break;
                case "DELE":
                    if (parts.Length > 1)
                    {
                        if (int.TryParse(parts[1], out int messageNumber) && messageNumber > 0 && messageNumber <= mailbox.Count && !deletedMessages[messageNumber - 1])
                        {
                            deletedMessages[messageNumber - 1] = true;
                            SendLine(stream, $"+OK Message {messageNumber} deleted.");
                        }
                        else
                        {
                            SendLine(stream, "-ERR No such message.");
                        }
                    }
                    else
                    {
                        SendLine(stream, "-ERR Missing message number.");
                    }
                    break;
                case "NOOP":
                    SendLine(stream, "+OK");
                    break;
                case "RSET":
                    for (int i = 0; i < deletedMessages.Count; i++)
                    {
                        deletedMessages[i] = false;
                    }
                    SendLine(stream, "+OK");
                    break;
                case "QUIT":
                    SendLine(stream, "+OK Goodbye");
                    // 在QUIT命令下，执行真正的删除操作并更新文件
                    string userMailboxPath = Path.Combine(MailboxRootPath, MailBoxesToDirName(currentUser) ?? "");
                    for (int i = mailbox.Count - 1; i >= 0; i--)
                    {
                        if (deletedMessages[i] && Directory.Exists(userMailboxPath))
                        {
                            string filePath = Path.Combine(userMailboxPath, $"{uidlList[i]}.eml");
                            if (File.Exists(filePath))
                            {
                                File.Delete(filePath);
                            }
                        }
                    }
                    state = POP3State.Update; // 进入更新状态，等待连接关闭
                    break;
                default:
                    SendLine(stream, "-ERR Invalid command in Transaction state.");
                    break;
            }
        }

        // 从文件系统加载用户的邮箱（读取原始字节，保留 UTF-8）
        private static void LoadMailboxForUser(string directoryName, out List<byte[]> mailbox, out List<string> uidlList)
        {
            mailbox = new List<byte[]>();
            uidlList = new List<string>();
            string userMailboxPath = Path.Combine(MailboxRootPath, directoryName ?? "");

            if (Directory.Exists(userMailboxPath))
            {
                string[] files = Directory.GetFiles(userMailboxPath, "*.eml");
                foreach (string filePath in files)
                {
                    try
                    {
                        mailbox.Add(File.ReadAllBytes(filePath));
                        // 使用文件名（不含扩展名）作为UIDL
                        uidlList.Add(Path.GetFileNameWithoutExtension(filePath));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error reading email file: {e.Message}");
                    }
                }
            }
            else
            {
                // 如果目录不存在，为新用户创建一个空邮箱
                Directory.CreateDirectory(userMailboxPath);
            }
        }

        #region Stream Helpers

        // 按行读取客户端命令（兼容 \r\n 与 \n，去掉行尾）
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
            return Encoding.ASCII.GetString(buf.ToArray());
        }

        // 发送一行响应（统一 CRLF 行尾）
        private static void SendLine(NetworkStream stream, string line)
        {
            byte[] data = Encoding.ASCII.GetBytes(line + "\r\n");
            stream.Write(data, 0, data.Length);
            stream.Flush();
        }

        // 将原始消息拆分为行（兼容 CRLF / LF / 单独 CR）
        private static List<byte[]> SplitLines(byte[] raw)
        {
            List<byte[]> lines = new List<byte[]>();
            List<byte> line = new List<byte>();
            int i = 0;
            while (i < raw.Length)
            {
                byte b = raw[i];
                if (b == (byte)'\n')
                {
                    lines.Add(line.ToArray());
                    line.Clear();
                    i++;
                }
                else if (b == (byte)'\r')
                {
                    if (i + 1 < raw.Length && raw[i + 1] == (byte)'\n')
                    {
                        lines.Add(line.ToArray());
                        line.Clear();
                        i += 2;
                    }
                    else
                    {
                        lines.Add(line.ToArray());
                        line.Clear();
                        i++;
                    }
                }
                else
                {
                    line.Add(b);
                    i++;
                }
            }
            if (line.Count > 0) lines.Add(line.ToArray());
            return lines;
        }

        // 组装为 CRLF 结尾并做 dot-stuffing（RFC 1939 §3）的传输字节，不含终止点
        private static byte[] PrepareMessageBytes(byte[] raw)
        {
            return BuildTransferBytes(SplitLines(raw));
        }

        // TOP：取头部（含分隔空行）+ 正文前 n 行（RFC 1939 §7）
        private static byte[] PrepareTopBytes(byte[] raw, int lines)
        {
            List<byte[]> allLines = SplitLines(raw);

            int bodyStart = allLines.Count;
            for (int i = 0; i < allLines.Count; i++)
            {
                if (allLines[i].Length == 0)
                {
                    bodyStart = i + 1;
                    break;
                }
            }

            List<byte[]> output = new List<byte[]>();
            int headerCount = Math.Min(bodyStart, allLines.Count);
            for (int i = 0; i < headerCount; i++) output.Add(allLines[i]);

            int bodyCount = Math.Max(0, Math.Min(lines, allLines.Count - bodyStart));
            for (int i = 0; i < bodyCount; i++) output.Add(allLines[bodyStart + i]);

            return BuildTransferBytes(output);
        }

        private static byte[] BuildTransferBytes(IEnumerable<byte[]> lines)
        {
            List<byte> outBytes = new List<byte>();
            foreach (byte[] line in lines)
            {
                if (line.Length > 0 && line[0] == (byte)'.')
                {
                    outBytes.Add((byte)'.');
                }
                outBytes.AddRange(line);
                outBytes.Add((byte)'\r');
                outBytes.Add((byte)'\n');
            }
            return outBytes.ToArray();
        }

        #endregion

        // 将邮箱地址转换为目录名
        public static string MailBoxesToDirName(string address)
        {
            string[] parts = address.Split('@', StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2)
            {
                return null;// Invalid address format
            }

            string domain = parts[1];
            string user = parts[0];

            user = new Regex("[+].*$").Replace(user, ""); // remove things after + from username.
            user = user.Replace(".", ""); //remove any dots from username;
            user = user.ToLower(); // lowercase all

            return $@"{user}_{domain}";
        }

        // 防止目录穿越 / 非法路径字符
        private static bool IsValidDirName(string dirName)
        {
            if (string.IsNullOrEmpty(dirName)) return false;
            if (dirName.Contains("..")) return false;
            if (dirName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return false;
            if (dirName.IndexOfAny(new[] { '/', '\\' }) >= 0) return false;
            return true;
        }
    }
}
