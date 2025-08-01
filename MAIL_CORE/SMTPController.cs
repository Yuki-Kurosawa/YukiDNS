using Microsoft.AspNetCore.Mvc;
using MimeKit;
using System;
using System.IO;
using System.Text;
using System.Xml.Linq;

namespace YukiDNS.MAIL_CORE
{
    [Route("/smtp"),Route("/mail")]
    public class SMTPController : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {

            string mailboxHTML = "";

            DirectoryInfo dir = new DirectoryInfo("maildb");

            var mbs = dir.GetDirectories("*", SearchOption.TopDirectoryOnly);

            foreach(DirectoryInfo mb in mbs)
            {
                string name = mb.Name;

                if (name == "queue") continue; // ignore queue folder

                mailboxHTML += $@"<a href='/mail/{name}'>{name.Replace("_","@")}</a><br/>" + "\r\n";
            }

            return File(Encoding.UTF8.GetBytes(
$@"<meta charset=""utf-8"" />
本地址目前用于查看内部邮件系统地址列表。<br/>
注意：<br/>
1. 本页面及子页面无需鉴权即可访问。<br/>
2. 请勿将邮件地址用于账户验证等高安全性用途或者业务邮件等可能具有保密性的用途<br/>
3. 本页面可能会被搜索引擎索引。<br/>
<hr/>
{mailboxHTML}
<hr/>
"), "text/html");
        }

        [HttpGet("{mailbox}")]
        public IActionResult MailBoxIndex(string mailbox)
        {
            string mailaddr = mailbox.Replace("_", "@");

            DirectoryInfo dir = new DirectoryInfo(Path.Combine("maildb",mailbox));
            var files = dir.GetFiles("*.eml", SearchOption.TopDirectoryOnly);

            string mailHTML = "";

            foreach(FileInfo file in files)
            {
                mailHTML += $@"<a href='/mail/{mailbox}/{file.Name}'>{GetMailTitle(file)}<br/>" + "\r\n";
            }

            return File(Encoding.UTF8.GetBytes(
$@"<meta charset=""utf-8"" />
{mailaddr} 的收件箱<br/>
<hr/>
{mailHTML}
<hr/>"), "text/html");
        }

        private string GetMailTitle(FileInfo file)
        {
            string path = file.FullName;
            MimeMessage msg = MimeMessage.Load(path);
            return $@"{msg.Subject}</a>&nbsp;{msg.Date.DateTime:yyyy-mm-dd HH:mm:ss}";
        }

        [HttpGet("{mailbox}/{eml}")]
        public IActionResult MailContent(string mailbox, string eml)
        {
            string path = Path.Combine("maildb", mailbox, eml);

            string html = $@"<meta charset=""utf-8"" />";

            MimeMessage msg = MimeMessage.Load(path);

            html += $@"发件人: {SafeQoute(msg.From.ToString())} <br/>" + "\r\n";
            html += $@"收件人: ";

            foreach (MailboxAddress to in msg.To)
            {
                html += SafeQoute(to.ToString()) + "; ";
            }
            html += "\r\n<br/>\r\n";

            html += "邮件主题: " + msg.Subject + "\r\n";
            html += "<hr/>\r\n<div>";

            if (!string.IsNullOrEmpty(msg.HtmlBody))
            {
                html += msg.HtmlBody;
            }
            else
            {
                html += msg.TextBody;
            }

            html += "</div>\r\n<hr/>";

            return File(Encoding.UTF8.GetBytes(html), "text/html");
        }

        private string SafeQoute(string address)
        {
            return address.Replace("\"", "").Replace("<", "&lt;").Replace(">", "&gt;");
        }
    }
}
