using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace PassedBall.TestWebApplication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        // GET api/auth
        [HttpGet]
        [AllowAnonymous]
        public ActionResult<IEnumerable<string>> Get()
        {
            // Should any additionaly auth types become supported
            // by this web app, add the name here.
            return new string[] { "Basic", "Digest", "NTLM", "Anonymous" };
        }

        // GET api/auth/anonymous
        [HttpGet("anonymous")]
        [AllowAnonymous]
        public ActionResult<string> GetAnonymous()
        {
            return "Successfully navigated with anonymous access";
        }

        // GET api/auth/basic
        [HttpGet("basic")]
        [Authorize(AuthenticationSchemes = "Basic")]
        public ActionResult<string> GetBasic()
        {
            return "Successfully authorized using HTTP Basic authentication";
        }

        // GET api/auth/digest
        [HttpGet("digest")]
        [Authorize(AuthenticationSchemes = "Digest")]
        public ActionResult<string> GetDigest()
        {
            return "Successfully authorized using HTTP Digest authentication";
        }

        // GET api/auth/ntlm
        [HttpGet("ntlm")]
        [Authorize(AuthenticationSchemes = "Windows")]
        public ActionResult<string> GetNtlm()
        {
            return "Successfully authorized using NTLM authentication";
        }
    }
}
