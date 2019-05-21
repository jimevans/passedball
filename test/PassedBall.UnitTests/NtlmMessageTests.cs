using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PassedBall.UnitTests
{
    [TestFixture]
    public class NtlmMessageTests
    {
        private string expectedType1 = "TlRMTVNTUAABAAAAAYIIogAAAAAoAAAAAAAAACgAAAAFASgKAAAADw==";
        private string type2Challenge = "TlRMTVNTUAACAAAAHgAeADgAAAAFgoqiHZv9GyiTGzEAAAAAAAAAAJgAmABWAAAACgDOSQAAAA9EAEUAUwBLAFQATwBQAC0ANQAzADYAMQA5ADQASQACAB4ARABFAFMASwBUAE8AUAAtADUAMwA2ADEAOQA0AEkAAQAeAEQARQBTAEsAVABPAFAALQA1ADMANgAxADkANABJAAQAHgBEAEUAUwBLAFQATwBQAC0ANQAzADYAMQA5ADQASQADAB4ARABFAFMASwBUAE8AUAAtADUAMwA2ADEAOQA0AEkABwAIAPD8+wtgC9UBAAAAAA==";
        private string expectedType3 = "TlRMTVNTUAADAAAAGAAYAEgAAADIAMgAYAAAAAAAAAAoAQAADgAOACgBAAAAAAAANgEAAAAAAAA2AQAABYKKogUBKAoAAAAP8dP6yZCfwpmUr42lg3M18Sl+CFn5zwo2rCW+HBdXjohOb2gzObgJjQEBAAAAAAAAAKijoT8L1QHbmgd46/JjXwAAAAACAB4ARABFAFMASwBUAE8AUAAtADUAMwA2ADEAOQA0AEkAAQAeAEQARQBTAEsAVABPAFAALQA1ADMANgAxADkANABJAAQAHgBEAEUAUwBLAFQATwBQAC0ANQAzADYAMQA5ADQASQADAB4ARABFAFMASwBUAE8AUAAtADUAMwA2ADEAOQA0AEkABwAIAPD8+wtgC9UBAAAAAAAAAABhAGwAYQBkAGQAaQBuAA==";
        private string userName = "aladdin";
        private string password = "OpenSesame";
        private DateTime testTime = new DateTime(2019, 5, 15, 17, 0, 0);
        private Random randomNumberGenerator = new Random(38267);

        [Test]
        public void NegotiateMessage()
        {
            NtlmNegotiateMessageGenerator generator = new NtlmNegotiateMessageGenerator(null, null);
            byte[] actualAuthBytes = generator.GetAuthorizationBytes();
            string actualAuthValue = generator.GetAuthorizationValue();

            string calculatedValue = Convert.ToBase64String(actualAuthBytes);
            Assert.That(calculatedValue, Is.EqualTo(expectedType1));
            Assert.That(actualAuthValue, Is.EqualTo(expectedType1));
        }

        [Test]
        public void ChallengeMessage()
        {
            NtlmChallengeMessageGenerator generator = new NtlmChallengeMessageGenerator(type2Challenge);
            string challenge = "HZv9GyiTGzE=";
            NtlmNegotiateFlags flags = NtlmNegotiateFlags.RequestUnicodeEncoding | NtlmNegotiateFlags.RequestTarget | NtlmNegotiateFlags.RequestNtlmV1 | NtlmNegotiateFlags.AlwaysSign | NtlmNegotiateFlags.TargetTypeServer | NtlmNegotiateFlags.RequestNtlmV2Session | NtlmNegotiateFlags.RequestTargetInfo | NtlmNegotiateFlags.RequestVersion | NtlmNegotiateFlags.Request128BitEncryption | NtlmNegotiateFlags.Request56BitEncryption;
            string target = "DESKTOP-536194I";
            string targetInfo = "AgAeAEQARQBTAEsAVABPAFAALQA1ADMANgAxADkANABJAAEAHgBEAEUAUwBLAFQATwBQAC0ANQAzADYAMQA5ADQASQAEAB4ARABFAFMASwBUAE8AUAAtADUAMwA2ADEAOQA0AEkAAwAeAEQARQBTAEsAVABPAFAALQA1ADMANgAxADkANABJAAcACADw/PsLYAvVAQAAAAA=";

            Assert.That(Convert.ToBase64String(generator.Challenge), Is.EqualTo(challenge));
            Assert.That(generator.Flags, Is.EqualTo(flags));
            Assert.That(Convert.ToBase64String(generator.TargetInfo), Is.EqualTo(targetInfo));
            Assert.That(generator.Target, Is.EqualTo(target));
        }

        [Test]
        public void AuthenticateMessage()
        {
            NtlmChallengeMessageGenerator type2Message = new NtlmChallengeMessageGenerator(type2Challenge);
            NtlmAuthenticateMessageGenerator generator = new NtlmAuthenticateMessageGenerator(randomNumberGenerator, testTime, null, null, userName, password, type2Message.Challenge, type2Message.Flags, type2Message.Target, type2Message.TargetInfo);
            byte[] actualAuthBytes = generator.GetAuthorizationBytes();
            string actualAuthValue = generator.GetAuthorizationValue();

            string calculatedValue = Convert.ToBase64String(actualAuthBytes);
            Assert.That(calculatedValue, Is.EqualTo(expectedType3));
            Assert.That(actualAuthValue, Is.EqualTo(expectedType3));
        }
    }
}
