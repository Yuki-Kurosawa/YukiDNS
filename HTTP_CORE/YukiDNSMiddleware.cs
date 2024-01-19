using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Threading.Tasks;

namespace YukiDNS.HTTP_CORE
{
    public class YukiDNSMiddleware
    {
        private readonly RequestDelegate _next;

        public YukiDNSMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            context.Response.Headers["Server"] = $"YukiDNS/1.0";

            await _next(context);
        }
    }
}