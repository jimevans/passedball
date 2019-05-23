using System.Threading.Tasks;
using Bazinga.AspNetCore.Authentication.Basic;

namespace PassedBall.TestWebApplication
{
    public class BasicAuthCredentialValidator : IBasicCredentialVerifier
    {
        private readonly string userName;
        private readonly string password;

        public BasicAuthCredentialValidator(string userName, string password)
        {
            this.userName = userName;
            this.password = password;
        }

        public Task<bool> Authenticate(string username, string password)
        {
            return Task.FromResult(username == this.userName && password == this.password);
        }

        public Task<bool> ValidateCredentials((string UserName, string Password) credentials)
        {
            return Authenticate(credentials.UserName, credentials.Password);
        }
    }
}
