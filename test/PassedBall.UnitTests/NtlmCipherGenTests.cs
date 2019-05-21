using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PassedBall.UnitTests
{
    [TestFixture]
    public class NtlmCipherGenTests
    {
        // Expected values derived from http://davenport.sourceforge.net/ntlm.html
        private Random rnd = new Random();
        private DateTime testDateTime = new DateTime(2003, 6, 17, 6, 0, 0);
        private string target = "DOMAIN";
        private string userName = "user";
        private string password = "SecREt01";
        private byte[] challenge = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
        private byte[] targetInfo = new byte[] { 0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x4f, 0x00,
                                                 0x4d, 0x00, 0x41, 0x00, 0x49, 0x00, 0x4e, 0x00,
                                                 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x45, 0x00,
                                                 0x52, 0x00, 0x56, 0x00, 0x45, 0x00, 0x52, 0x00,
                                                 0x04, 0x00, 0x14, 0x00, 0x64, 0x00, 0x6f, 0x00,
                                                 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
                                                 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00,
                                                 0x03, 0x00, 0x22, 0x00, 0x73, 0x00, 0x65, 0x00,
                                                 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
                                                 0x2e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x6d, 0x00,
                                                 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x2e, 0x00,
                                                 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x00, 0x00,
                                                 0x00, 0x00 };
        private byte[] clientNonce = new byte[] { 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44 };
        private byte[] secondaryKey = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        private byte[] timestamp = BitConverter.GetBytes(127003176000000000);

        [Test]
        public void GetLmResponse()
        {
            string expectedLmResponse = "wzfNXL1E/JeCpmevbUJ8beZ8IMLT53xW";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] lmResponse = generator.GetLmResponse();
            string actual = Convert.ToBase64String(lmResponse);
            Assert.That(actual, Is.EqualTo(expectedLmResponse));
        }

        [Test]
        public void GetNtlmResponse()
        {
            string expectedNtlmResponse = "JamMHDHoGEdGaymy30aA85lY+4whOpzG";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] ntlmResponse = generator.GetNtlmResponse();
            string actual = Convert.ToBase64String(ntlmResponse);
            Assert.That(actual, Is.EqualTo(expectedNtlmResponse));
        }

        [Test]
        public void GetLmV2Response()
        {
            string expectedLmV2Response = "1uYVLqJdA7fGumYpwtaq8P///wARIjNE";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] lmV2Response = generator.GetLmV2Response();
            string actual = Convert.ToBase64String(lmV2Response);
            Assert.That(actual, Is.EqualTo(expectedLmV2Response));
        }

        [Test]
        public void GetNtlmV2Response()
        {
            string expectedNtlmV2Response = "y6u8pxPreV0EyXq8Ae5JgwEBAAAAAAAAAJDTNrc0wwH///8AESIzRAAAAAACAAwARABPAE0AQQBJAE4AAQAMAFMARQBSAFYARQBSAAQAFABkAG8AbQBhAGkAbgAuAGMAbwBtAAMAIgBzAGUAcgB2AGUAcgAuAGQAbwBtAGEAaQBuAC4AYwBvAG0AAAAAAAAAAAA=";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] ntlmV2Response = generator.GetNtlmV2Response();
            string actual = Convert.ToBase64String(ntlmV2Response);
            Assert.That(actual, Is.EqualTo(expectedNtlmV2Response));
        }

        [Test]
        public void GetNtlm2SessionResponse()
        {
            string expectedNtlm2SessionResponse = "ENVQgy0Sssy3nVrR9O7T34KspMNoHdRV";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] ntlm2SessionResponse = generator.GetNtlm2SessionResponse();
            string actual = Convert.ToBase64String(ntlm2SessionResponse);
            Assert.That(actual, Is.EqualTo(expectedNtlm2SessionResponse));
        }

        [Test]
        public void GetLmUserSessionKey()
        {
            string expectedLmUserSessionKey = "/zdQvMKyJBIAAAAAAAAAAA==";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] lmUserSessionKey = generator.GetLmUserSessionKey();
            string actual = Convert.ToBase64String(lmUserSessionKey);
            Assert.That(actual, Is.EqualTo(expectedLmUserSessionKey));
        }

        [Test]
        public void GetNtlmUserSessionKey()
        {
            string expectedNtlmUserSessionKey = "Pzc+qOSvlU8U+qUG+O69xA==";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] ntlmUserSessionKey = generator.GetNtlmUserSessionKey();
            string actual = Convert.ToBase64String(ntlmUserSessionKey);
            Assert.That(actual, Is.EqualTo(expectedNtlmUserSessionKey));
        }

        [Test]
        public void GetNtlmV2UserSessionKey()
        {
            string expectedNtlmV2UserSesionKey = "uUojm7TG0ewIMGoHHSuQ8A==";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] ntlmV2UserSessionKey = generator.GetNtlmV2UserSessionKey();
            string actual = Convert.ToBase64String(ntlmV2UserSessionKey);
            Assert.That(actual, Is.EqualTo(expectedNtlmV2UserSesionKey));
        }

        [Test]
        public void GetLanManagerSessionKey()
        {
            string expectedLmSessionKey = "jMEGW8eZESyhFx1Q/eT13g==";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] lmSessionKey = generator.GetLanManagerSessionKey();
            string actual = Convert.ToBase64String(lmSessionKey);
            Assert.That(actual, Is.EqualTo(expectedLmSessionKey));
        }

        [Test]
        public void GetNtlm2SessionResponseUserSessionKey()
        {
            string expectedNtlm2SessionResponseUserSessionKey = "qW9E2Ey2jPsj/AS7rzgeVA==";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] ntlm2SessionResponseUserSessionKey = generator.GetNtlm2SessionResponseUserSessionKey();
            string actual = Convert.ToBase64String(ntlm2SessionResponseUserSessionKey);
            Assert.That(actual, Is.EqualTo(expectedNtlm2SessionResponseUserSessionKey));
        }

        [Test]
        public void GetLm2SessionResponse()
        {
            string expectedLm2SessionResponse = "////ABEiM0QAAAAAAAAAAAAAAAAAAAAA";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] lm2SessionResponse = generator.GetLm2SessionResponse();
            string actual = Convert.ToBase64String(lm2SessionResponse);
            Assert.That(actual, Is.EqualTo(expectedLm2SessionResponse));
        }

        [Test]
        public void GetSecondaryKey()
        {
            string expectedSecondaryKey = "AAECAwQFBgcICQoLDA0ODw==";
            CipherGen generator = new CipherGen(rnd, testDateTime, target, userName, password, challenge, target, targetInfo, clientNonce, clientNonce, secondaryKey, timestamp);
            byte[] secondaryKeyValue = generator.GetSecondaryKey();
            string actual = Convert.ToBase64String(secondaryKeyValue);
            Assert.That(actual, Is.EqualTo(expectedSecondaryKey));
        }
    }
}
