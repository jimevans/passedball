using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;
using NUnit.Framework;

namespace PassedBall.IntegrationTests
{
    [TestFixture]
    public class EnvironmentPreparationTests
    {
        [Test]
        public void EnvironmentIsWindows()
        {
            Assert.That(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), Is.True, "Running integration tests requires Windows, as NTLM authentication will not work otherwise.");
        }

        [Test]
        public void LocalNtlmUserExists()
        {
            string userName = "PassedBallAuthUser";
            string password = "PassedBallP@ssw0rd!";
            using (PrincipalContext context = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, userName);
                Assert.That(user, Is.Not.Null, "To successfully run the NTLM auth test you need a local Windows user with name {0} and password {1}.", userName, password);
            }
        }
    }
}
