using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace YukiDNS.MAIL_CORE
{
    [Route("/smtp"),Route("/mail")]
    public class SMTPController : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            return File(Encoding.UTF8.GetBytes(
@"<meta charset=""utf-8"" />
本地址目前用于查看内部邮件系统地址列表。<br/>
注意：<br/>
1. 本页面及子页面无需鉴权即可访问。<br/>
2. 请勿将邮件地址用于账户验证等高安全性用途或者业务邮件等可能具有保密性的用途<br/>
3. 本页面可能会被搜索引擎索引。<br/>
"), "text/html");
        }
    }
}
