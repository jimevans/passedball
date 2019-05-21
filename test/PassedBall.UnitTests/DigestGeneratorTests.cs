using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PassedBall.UnitTests
{
    [TestFixture]
    public class DigestGeneratorTests
    {
        private string userName = "user.name";
        private string password = "s3cr3tP@ssw0rd";
        private string httpVerb = "GET";
        private string url = "/login";
        private string authenticationHeader = "realm=\"test.dev\", nonce=\"064af982c5b571cea6450d8eda91c20d\", domain=\"/login\", opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\", qop=auth";

        [Test]
        public void TestDigest()
        {
            string expectedHeaderValue = "Digest username=\"user.name\", realm=\"test.dev\", nonce=\"064af982c5b571cea6450d8eda91c20d\", uri=\"/login\", response=\"70eda34f1683041fd9ab72056c51b740\", qop=auth, nc=00000001, cnonce=\"61417766e50cb980\", algorithm=MD5, opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\"";
            DigestGenerator generator = new DigestGenerator(userName, password, httpVerb, url, "61417766e50cb980", 1, authenticationHeader);
            string expectedResponse = "70eda34f1683041fd9ab72056c51b740";

            Assert.That(generator.GetAuthorizationValue(), Is.EqualTo(expectedResponse));
            string ff = generator.GenerateAuthorizationHeader();
            Assert.That(generator.GenerateAuthorizationHeader(), Is.EqualTo(expectedHeaderValue));
        }

        [Test]
        public void NullUserNameThrowsException()
        {
            Assert.That(() => new DigestGenerator(null, password, httpVerb, url, authenticationHeader), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void NullPasswordThrowsException()
        {
            Assert.That(() => new DigestGenerator(userName, null, httpVerb, url, authenticationHeader), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void NullHttpVerbThrowsException()
        {
            Assert.That(() => new DigestGenerator(userName, password, null, url, authenticationHeader), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void NullUrlThrowsException()
        {
            Assert.That(() => new DigestGenerator(userName, password, httpVerb, null, authenticationHeader), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void NullAuthHeaderThrowsException()
        {
            Assert.That(() => new DigestGenerator(userName, password, httpVerb, url, null), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void EmptyUserNameThrowsException()
        {
            Assert.That(() => new DigestGenerator(string.Empty, password, httpVerb, url, authenticationHeader), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void EmptyPasswordThrowsException()
        {
            Assert.That(() => new DigestGenerator(userName, string.Empty, httpVerb, url, authenticationHeader), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void EmptyHttpVerbThrowsException()
        {
            Assert.That(() => new DigestGenerator(userName, password, string.Empty, url, authenticationHeader), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void EmptyUrlThrowsException()
        {
            Assert.That(() => new DigestGenerator(userName, password, httpVerb, string.Empty, authenticationHeader), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void EmptyAuthHeaderThrowsException()
        {
            Assert.That(() => new DigestGenerator(userName, password, httpVerb, url, string.Empty), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void UnknownAlgorithmInAuthHeaderThrowsException()
        {
            string badAuthenticationHeader = "realm=\"test.dev\", nonce=\"064af982c5b571cea6450d8eda91c20d\", domain=\"/login\", opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\", qop=auth, algorithm=DES";
            Assert.That(() => new DigestGenerator(userName, password, httpVerb, url, badAuthenticationHeader), Throws.InstanceOf<ArgumentException>());
        }

        [Test]
        public void UnknownQopInAuthHeaderThrowsException()
        {
            string badAuthenticationHeader = "realm=\"test.dev\", nonce=\"064af982c5b571cea6450d8eda91c20d\", domain=\"/login\", opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\", qop=invalid";
            Assert.That(() => new DigestGenerator(userName, password, httpVerb, url, badAuthenticationHeader), Throws.InstanceOf<ArgumentException>());
        }
    }
}
