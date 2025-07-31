using System;
using System.Collections.Generic;
using System.IO; // Required for StreamReader, StreamWriter, and File operations
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace YukiDNS.MAIL_CORE
{
    public class SMTPService
    {
        // Define the directory where received emails will be saved
        private static readonly string EmailSaveDirectory = "ReceivedEmails";

        public static void Start()
        {
            // Ensure the save directory exists
            if (!Directory.Exists(EmailSaveDirectory))
            {
                Directory.CreateDirectory(EmailSaveDirectory);
            }

            Thread smtp = new Thread(SMTP_THREAD_TCP);
            smtp.Start();
            Console.WriteLine("SMTPService started, listening on port 25...");
            Console.WriteLine($"Emails will be saved to: {Path.GetFullPath(EmailSaveDirectory)}");
        }

        private static void SMTP_THREAD_TCP()
        {
            // Listen to SMTP RFC PORT 25 on all available network interfaces
            TcpListener tcp = new TcpListener(new IPEndPoint(IPAddress.Any, 25));
            tcp.Start();

            while (true)
            {
                // Accept a new client connection
                TcpClient client = null;
                NetworkStream stream = null;
                StreamReader reader = null;
                StreamWriter writer = null;

                try
                {
                    client = tcp.AcceptTcpClientAsync().Result;
                    stream = client.GetStream();
                    reader = new StreamReader(stream, Encoding.ASCII);
                    writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

                    Console.WriteLine($"Client connected from {((IPEndPoint)client.Client.RemoteEndPoint).Address}");

                    // Define SMTP states
                    // enum SmtpState { Initial, HeloReceived, MailFromReceived, RcptToReceived, DataMode };
                    SmtpState currentState = SmtpState.Initial;

                    // Store email details
                    string mailFrom = string.Empty;
                    List<string> rcptTo = new List<string>();
                    StringBuilder emailData = new StringBuilder();

                    // Send initial 220 Service Ready response
                    SendResponse(writer, "220 localhost.ksyuki.com SMTP Service Ready");

                    string requestLine;
                    while (client.Connected && (requestLine = reader.ReadLine()) != null)
                    {
                        string request = requestLine.Trim();
                        if (string.IsNullOrEmpty(request)) continue;

                        Console.WriteLine($"Received: {request}");

                        // Process SMTP commands based on current state
                        if (currentState == SmtpState.DataMode)
                        {
                            // In DATA mode, collect all lines until a line with "."
                            if (request == ".")
                            {
                                Console.WriteLine("End of DATA received.");
                                Console.WriteLine("--- Email Content Summary ---");
                                Console.WriteLine($"Mail From: {mailFrom}");
                                Console.WriteLine($"Recipients: {string.Join(", ", rcptTo)}");
                                Console.WriteLine("-----------------------------");

                                // --- NEW: Save the received email to a file ---
                                string fileName = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid().ToString().Substring(0, 8)}.eml";
                                string filePath = Path.Combine(EmailSaveDirectory, fileName);

                                try
                                {
                                    File.WriteAllText(filePath, emailData.ToString());
                                    Console.WriteLine($"Email saved to: {filePath}");
                                    SendResponse(writer, "250 OK: Message accepted for delivery and saved");
                                }
                                catch (Exception fileEx)
                                {
                                    Console.WriteLine($"ERROR: Could not save email to file {filePath}: {fileEx.Message}");
                                    SendResponse(writer, "451 Requested action aborted: local error in processing");
                                }
                                // --- END NEW ---

                                // Reset state for next email from same client
                                emailData.Clear();
                                mailFrom = string.Empty;
                                rcptTo.Clear();
                                currentState = SmtpState.HeloReceived; // Back to a state where new MAIL FROM is expected
                            }
                            else
                            {
                                // Append the received line to emailData, re-adding CRLF for proper .eml format
                                emailData.Append(requestLine + "\r\n");
                            }
                        }
                        else
                        {
                            // Process SMTP commands
                            string command = request.ToUpper();
                            if (command.StartsWith("EHLO ") || command.StartsWith("HELO "))
                            {
                                SendResponse(writer, "250-localhost.ksyuki.com Hello");
                                SendResponse(writer, "250-PIPELINING");
                                SendResponse(writer, "250-SIZE 10240000"); // Example max size
                                SendResponse(writer, "250-VRFY");
                                SendResponse(writer, "250-ETRN");
                                SendResponse(writer, "250-AUTH PLAIN LOGIN"); // Example auth methods
                                SendResponse(writer, "250-ENHANCEDSTATUSCODES");
                                SendResponse(writer, "250-8BITMIME");
                                SendResponse(writer, "250-DSN");
                                SendResponse(writer, "250 SMTPUTF8"); // Last 250 response
                                currentState = SmtpState.HeloReceived;
                            }
                            else if (command.StartsWith("MAIL FROM:"))
                            {
                                mailFrom = request.Substring("MAIL FROM:".Length).Trim();
                                SendResponse(writer, "250 OK");
                                currentState = SmtpState.MailFromReceived;
                            }
                            else if (command.StartsWith("RCPT TO:"))
                            {
                                rcptTo.Add(request.Substring("RCPT TO:".Length).Trim());
                                SendResponse(writer, "250 OK");
                                currentState = SmtpState.RcptToReceived;
                            }
                            else if (command == "DATA")
                            {
                                if (currentState == SmtpState.RcptToReceived) // Must have recipient before DATA
                                {
                                    SendResponse(writer, "354 Start mail input; end with <CRLF>.<CRLF>");
                                    currentState = SmtpState.DataMode;
                                }
                                else
                                {
                                    SendResponse(writer, "503 Bad sequence of commands");
                                }
                            }
                            else if (command == "RSET")
                            {
                                mailFrom = string.Empty;
                                rcptTo.Clear();
                                emailData.Clear();
                                currentState = SmtpState.HeloReceived;
                                SendResponse(writer, "250 OK");
                            }
                            else if (command == "NOOP")
                            {
                                SendResponse(writer, "250 OK");
                            }
                            else if (command == "QUIT")
                            {
                                SendResponse(writer, "221 Bye");
                                Console.WriteLine("Client requested QUIT. Closing connection.");
                                break; // Exit inner while loop to close client connection
                            }
                            else
                            {
                                SendResponse(writer, "502 Command not implemented");
                            }
                        }
                    }
                }
                catch (IOException ex) // Catch IO exceptions for disconnected clients
                {
                    Console.WriteLine($"Client disconnected unexpectedly or IO error: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during SMTP session: {ex.Message}");
                }
                finally
                {
                    // Ensure all resources are closed
                    if (writer != null) writer.Dispose();
                    if (reader != null) reader.Dispose();
                    if (stream != null) stream.Close();
                    if (client != null) client.Close();
                    Console.WriteLine("Client connection closed.");
                }
            }
        }

        // Helper method to send responses to the client using StreamWriter
        private static void SendResponse(StreamWriter writer, string response)
        {
            writer.WriteLine(response);
            Console.WriteLine($"Sent: {response}");
        }
    }
}
