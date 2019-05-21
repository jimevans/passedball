using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PassedBall.UnitTests
{
    [TestFixture]
    public class BasicGeneratorTests
    {
        private string userName = "Aladdin";
        private string password = "open sesame";
        private string expectedValue = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";

        [Test]
        public void TestUserNameAndPassword()
        {
            BasicGenerator generator = new BasicGenerator(userName, password);
            byte[] actualAuthBytes = generator.GetAuthorizationBytes();
            string actualAuthValue = generator.GetAuthorizationValue();

            string calculatedValue = Convert.ToBase64String(actualAuthBytes);
            Assert.That(calculatedValue, Is.EqualTo(expectedValue));
            Assert.That(actualAuthValue, Is.EqualTo(expectedValue));
        }

        [Test]
        public void TestUserNamePasswordAndHeader()
        {
            string header = "realm=\"Protected Area\", charset=\"UTF-8\"";
            BasicGenerator generator = new BasicGenerator(userName, password, header);
            byte[] actualAuthBytes = generator.GetAuthorizationBytes();
            string actualAuthValue = generator.GetAuthorizationValue();

            string calculatedValue = Convert.ToBase64String(actualAuthBytes);
            Assert.That(calculatedValue, Is.EqualTo(expectedValue));
            Assert.That(actualAuthValue, Is.EqualTo(expectedValue));
        }

        [Test]
        public void TestUserNamePasswordAndNullHeader()
        {
            BasicGenerator generator = new BasicGenerator(userName, password, null);
            byte[] actualAuthBytes = generator.GetAuthorizationBytes();
            string actualAuthValue = generator.GetAuthorizationValue();

            string calculatedValue = Convert.ToBase64String(actualAuthBytes);
            Assert.That(calculatedValue, Is.EqualTo(expectedValue));
            Assert.That(actualAuthValue, Is.EqualTo(expectedValue));
        }

        [Test]
        public void NullUserNameThrowsException()
        {
            Assert.That(() => new BasicGenerator(null, password), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void NullPasswordThrowsException()
        {
            Assert.That(() => new BasicGenerator(userName, null), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void EmptyUserNameThrowsException()
        {
            Assert.That(() => new BasicGenerator(string.Empty, password), Throws.InstanceOf<ArgumentNullException>());
        }

        [Test]
        public void EmptyPasswordThrowsException()
        {
            Assert.That(() => new BasicGenerator(userName, string.Empty), Throws.InstanceOf<ArgumentNullException>());
        }
    }
}
