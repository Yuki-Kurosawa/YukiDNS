using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using YukiDNS.COMMON_CORE.Constants;
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
        // 邮件根目录，根据日志信息设置
        private const string MailboxRootPath = @"maildb";

        public static void Start()
        {
            Thread pop3 = new Thread(POP3_THREAD_TCP);
            pop3.Start();
            Console.WriteLine("POP3Service started, listening on port 110...");
        }

        private static void POP3_THREAD_TCP()
        {
            int port = 110;
            TcpListener server = null;
            try
            {
                IPAddress localAddr = IPAddress.Any;
                server = new TcpListener(localAddr, port);
                server.Start();

                while (true)
                {
                    Console.WriteLine("Waiting for a POP3 connection...");
                    TcpClient client = server.AcceptTcpClient();
                    Console.WriteLine("Connected!");
                    Thread clientThread = new Thread(() => HandleClient(client));
                    clientThread.Start();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
            finally
            {
                if (server != null)
                {
                    server.Stop();
                }
            }
        }

        private static void HandleClient(TcpClient client)
        {
            StreamReader reader = null;
            StreamWriter writer = null;
            POP3State state = POP3State.Authorization;
            string currentUser = null;

            // 声明本地邮件列表，在登录成功后加载
            List<string> mailbox = new List<string>();
            List<string> uidlList = new List<string>();
            List<bool> deletedMessages = new List<bool>();

            try
            {
                NetworkStream stream = client.GetStream();
                reader = new StreamReader(stream, Encoding.ASCII);
                writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

                writer.WriteLine("+OK POP3 server ready");
                Console.WriteLine("Sent: +OK POP3 server ready");

                string command;
                while ((command = reader.ReadLine()) != null)
                {
                    Console.WriteLine("Received: {0}", command);
                    string[] parts = command.Split(' ');
                    string cmd = parts[0].ToUpper();

                    switch (state)
                    {
                        case POP3State.Authorization:
                            HandleAuthorizationState(cmd, parts, writer, ref currentUser, ref state, ref mailbox, ref uidlList, ref deletedMessages);
                            break;
                        case POP3State.Transaction:
                            // 传入 currentUser 变量
                            HandleTransactionState(cmd, parts, writer, ref state, currentUser, mailbox, uidlList, deletedMessages);
                            break;
                        case POP3State.Update:
                            writer.WriteLine("-ERR Invalid state for this command");
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
                if (reader != null) reader.Close();
                if (writer != null) writer.Close();
                if (client != null) client.Close();
                Console.WriteLine("Connection closed.");
            }
        }

        private static void HandleAuthorizationState(string cmd, string[] parts, StreamWriter writer, ref string currentUser, ref POP3State state, ref List<string> mailbox, ref List<string> uidlList, ref List<bool> deletedMessages)
        {
            switch (cmd)
            {
                case "CAPA":
                    writer.WriteLine("+OK Capability list follows");
                    writer.WriteLine("USER");
                    writer.WriteLine("UIDL");
                    writer.WriteLine("TOP");
                    writer.WriteLine(".");
                    break;
                case "USER":
                    if (parts.Length > 1)
                    {
                        string username = parts[1];
                        string userMailboxPath = Path.Combine(MailboxRootPath, MailBoxesToDirName(username));

                        // 验证用户邮箱目录是否存在
                        if (Directory.Exists(userMailboxPath))
                        {
                            currentUser = username;
                            writer.WriteLine($"+OK User {username} accepted. Please send PASS command.");
                            Console.WriteLine($"+OK User {username} accepted. Please send PASS command.");
                        }
                        else
                        {
                            writer.WriteLine("-ERR User does not exist.");
                            Console.WriteLine("-ERR User does not exist.");
                        }
                    }
                    else
                    {
                        writer.WriteLine("-ERR Missing username.");
                    }
                    break;
                case "PASS":
                    // 只有当currentUser不为空时，才处理PASS命令，这确保了USER命令的成功执行
                    if (currentUser != null && parts.Length > 1)
                    {
                        // 实际应用中，这里需要验证用户名和密码
                        // 为了演示，我们假设任何密码都有效
                        writer.WriteLine("+OK Logged in successfully.");
                        Console.WriteLine("+OK Logged in successfully.");

                        // 登录成功后，从文件系统加载邮件
                        string mailboxDir = MailBoxesToDirName(currentUser);
                        LoadMailboxForUser(mailboxDir, out mailbox, out uidlList);
                        deletedMessages = mailbox.Select(_ => false).ToList();

                        state = POP3State.Transaction; // 成功后进入事务状态
                    }
                    else
                    {
                        writer.WriteLine("-ERR Invalid command sequence or missing password.");
                    }
                    break;
                case "QUIT":
                    writer.WriteLine("+OK Goodbye");
                    state = POP3State.Update; // 进入更新状态，等待连接关闭
                    break;
                default:
                    writer.WriteLine("-ERR Invalid command in Authorization state.");
                    break;
            }
        }

        private static void HandleTransactionState(string cmd, string[] parts, StreamWriter writer, ref POP3State state, string currentUser, List<string> mailbox, List<string> uidlList, List<bool> deletedMessages)
        {
            switch (cmd)
            {
                case "STAT":
                    int emailCount = mailbox.Count(m => !deletedMessages[mailbox.IndexOf(m)]);
                    long totalSize = mailbox.Where(m => !deletedMessages[mailbox.IndexOf(m)]).Sum(e => Encoding.ASCII.GetBytes(e).Length);
                    writer.WriteLine($"+OK {emailCount} {totalSize}");
                    break;
                case "LIST":
                    writer.WriteLine("+OK Scan listing follows");
                    for (int i = 0; i < mailbox.Count; i++)
                    {
                        if (!deletedMessages[i])
                        {
                            long size = Encoding.ASCII.GetBytes(mailbox[i]).Length;
                            writer.WriteLine($"{i + 1} {size}");
                        }
                    }
                    writer.WriteLine(".");
                    break;
                case "RETR":
                    if (parts.Length > 1)
                    {
                        if (int.TryParse(parts[1], out int messageNumber) && messageNumber > 0 && messageNumber <= mailbox.Count && !deletedMessages[messageNumber - 1])
                        {
                            string emailContent = mailbox[messageNumber - 1];
                            long size = Encoding.ASCII.GetBytes(emailContent).Length;
                            writer.WriteLine($"+OK {size} octets");
                            writer.WriteLine(emailContent);
                            writer.WriteLine(".");
                        }
                        else
                        {
                            writer.WriteLine("-ERR No such message.");
                        }
                    }
                    else
                    {
                        writer.WriteLine("-ERR Missing message number.");
                    }
                    break;
                case "UIDL":
                    if (parts.Length > 1)
                    {
                        if (int.TryParse(parts[1], out int messageNumber) && messageNumber > 0 && messageNumber <= uidlList.Count && !deletedMessages[messageNumber - 1])
                        {
                            string uid = uidlList[messageNumber - 1];
                            writer.WriteLine($"+OK {messageNumber} {uid}");
                        }
                        else
                        {
                            writer.WriteLine("-ERR No such message.");
                        }
                    }
                    else
                    {
                        writer.WriteLine("+OK UIDL listing follows");
                        for (int i = 0; i < uidlList.Count; i++)
                        {
                            if (!deletedMessages[i])
                            {
                                writer.WriteLine($"{i + 1} {uidlList[i]}");
                            }
                        }
                        writer.WriteLine(".");
                    }
                    break;
                case "DELE":
                    if (parts.Length > 1)
                    {
                        if (int.TryParse(parts[1], out int messageNumber) && messageNumber > 0 && messageNumber <= mailbox.Count && !deletedMessages[messageNumber - 1])
                        {
                            deletedMessages[messageNumber - 1] = true;
                            writer.WriteLine($"+OK Message {messageNumber} deleted.");
                        }
                        else
                        {
                            writer.WriteLine("-ERR No such message.");
                        }
                    }
                    else
                    {
                        writer.WriteLine("-ERR Missing message number.");
                    }
                    break;
                case "QUIT":
                    writer.WriteLine("+OK Goodbye");
                    // 在QUIT命令下，执行真正的删除操作并更新文件
                    string userMailboxPath = Path.Combine(MailboxRootPath, MailBoxesToDirName(currentUser));
                    for (int i = mailbox.Count - 1; i >= 0; i--)
                    {
                        if (deletedMessages[i])
                        {
                            if (Directory.Exists(userMailboxPath))
                            {
                                string filePath = Path.Combine(userMailboxPath, $"{uidlList[i]}.eml");
                                if (File.Exists(filePath))
                                {
                                    File.Delete(filePath);
                                }
                            }
                        }
                    }
                    state = POP3State.Update; // 进入更新状态，等待连接关闭
                    break;
                default:
                    writer.WriteLine("-ERR Invalid command in Transaction state.");
                    break;
            }
        }

        // 新增方法：从文件系统加载用户的邮箱
        private static void LoadMailboxForUser(string directoryName, out List<string> mailbox, out List<string> uidlList)
        {
            mailbox = new List<string>();
            uidlList = new List<string>();
            string userMailboxPath = Path.Combine(MailboxRootPath, directoryName);

            if (Directory.Exists(userMailboxPath))
            {
                string[] files = Directory.GetFiles(userMailboxPath, "*.eml");
                foreach (string filePath in files)
                {
                    try
                    {
                        string content = File.ReadAllText(filePath);
                        mailbox.Add(content);
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

        // 新增辅助方法：将邮箱地址转换为目录名
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
    }
}
