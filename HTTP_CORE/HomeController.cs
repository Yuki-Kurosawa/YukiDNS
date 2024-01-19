using Microsoft.AspNetCore.Mvc;

namespace YukiDNS.HTTP_CORE
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return new ObjectResult("OK");
        }
    }
}
