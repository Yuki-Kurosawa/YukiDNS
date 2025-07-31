using System;
using System.Collections.Generic; // Required for List<string>
using System.IO; // Required for StreamReader and StreamWriter
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace YukiDNS.MAIL_CORE
{
    public class SMTPService
    {
        public static void Start()
        {
            Thread smtp = new Thread(SMTP_THREAD_TCP);
            smtp.Start();
            Console.WriteLine("SMTPService started, listening on port 25...");
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
                StreamReader reader = null; // New: For reading lines
                StreamWriter writer = null; // New: For writing lines

                try
                {
                    client = tcp.AcceptTcpClientAsync().Result;
                    stream = client.GetStream();
                    reader = new StreamReader(stream, Encoding.ASCII); // Initialize StreamReader
                    writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true }; // Initialize StreamWriter

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
                    while (client.Connected && (requestLine = reader.ReadLine()) != null) // Read line by line
                    {
                        string request = requestLine.Trim(); // Trim whitespace including CRLF
                        if (string.IsNullOrEmpty(request)) continue; // Ignore empty lines

                        Console.WriteLine($"Received: {request}");

                        // Process SMTP commands based on current state
                        if (currentState == SmtpState.DataMode)
                        {
                            // In DATA mode, collect all lines until a line with "."
                            if (request == ".")
                            {
                                Console.WriteLine("End of DATA received.");
                                Console.WriteLine("--- Email Content ---");
                                Console.WriteLine($"Mail From: {mailFrom}");
                                Console.WriteLine($"Recipients: {string.Join(", ", rcptTo)}");
                                Console.WriteLine(emailData.ToString());
                                Console.WriteLine("---------------------");

                                // Here you would typically save the email or forward it to hMailServer
                                // For example, you could create a new TcpClient to 127.0.0.2:25
                                // and send this emailData to hMailServer.

                                // Reset state for next email from same client
                                emailData.Clear();
                                mailFrom = string.Empty;
                                rcptTo.Clear();
                                currentState = SmtpState.HeloReceived; // Back to a state where new MAIL FROM is expected
                                SendResponse(writer, "250 OK: Message accepted for delivery");
                            }
                            else
                            {
                                emailData.AppendLine(request);
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
                    if (writer != null) writer.Dispose(); // Dispose StreamWriter
                    if (reader != null) reader.Dispose(); // Dispose StreamReader
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
            // AutoFlush is set to true in StreamWriter initialization, so no explicit Flush() needed here.
            Console.WriteLine($"Sent: {response}");
        }
    }
}
