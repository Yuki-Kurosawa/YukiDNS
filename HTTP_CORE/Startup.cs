using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace YukiDNS.HTTP_CORE
{
    /// <summary>
    /// Builtin HttpServer Startup
    /// </summary>
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IServiceProvider serviceProvider)
        {
            app.UseMiddleware<YukiDNSMiddleware>();

            var def = new DefaultFilesOptions()
            {
                DefaultFileNames = new[]
                {
                    "index.html",
                    "index.htm",
                    "default.html",
                    "default.htm"
                }
            };

            app.UseDefaultFiles(def);

            app.UseStaticFiles(new StaticFileOptions()
            {
                 ServeUnknownFileTypes= true,
                 DefaultContentType="application/octet-stream"
            });

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            AddCorsPolicy(services);
        }

        private void AddCorsPolicy(IServiceCollection services)
        {
            var corsBuilder = new CorsPolicyBuilder();
            corsBuilder.AllowAnyHeader();
            corsBuilder.AllowAnyMethod();
            corsBuilder.AllowAnyOrigin();
            corsBuilder.AllowCredentials();

            services.AddCors(options =>
            {
                options.AddPolicy("DefaultCorsPolicy", corsBuilder.Build());
            });
        }

    }
}
