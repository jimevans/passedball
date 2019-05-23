using System.Threading.Tasks;
using FlakeyBit.DigestAuthentication.Implementation;

namespace PassedBall.TestWebApplication
{
    public class DigestAuthCredentialValidator : IUsernameSecretProvider
    {
        private readonly string userName;
        private readonly string password;

        public DigestAuthCredentialValidator(string userName, string password)
        {
            this.userName = userName;
            this.password = password;
        }

        public string ServerNonce => "SecretServerNonce";

        public Task<string> GetSecretForUsernameAsync(string username)
        {
            if (username == this.userName)
            {
                return Task.FromResult(this.password);
            }

            // Return value of null indicates unknown (invalid) user
            return Task.FromResult<string>(null);
        }
    }
}
