using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.HttpSys;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Bazinga.AspNetCore.Authentication.Basic;
using FlakeyBit.DigestAuthentication.AspNetCore;
using FlakeyBit.DigestAuthentication.Implementation;

namespace PassedBall.TestWebApplication
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            BasicAuthCredentialValidator basicValidator = new BasicAuthCredentialValidator("farnsworth", "GoodNewsEveryone!");
            DigestAuthCredentialValidator digestValidator = new DigestAuthCredentialValidator("leela", "Nibbler");
            services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme).AddBasicAuthentication("Basic", (options) => { options.Realm = "Basic Auth Realm"; }, basicValidator.ValidateCredentials);
            services.AddAuthentication("Digest").AddDigestAuthentication(DigestAuthenticationConfiguration.Create(digestValidator.ServerNonce, "Digest Auth Realm"), digestValidator);
            services.AddAuthentication(HttpSysDefaults.AuthenticationScheme);
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseMvc();
        }
    }
}
