using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.HttpSys;
using NUnit.Framework;
using PassedBall.TestWebApplication;

namespace PassedBall.IntegrationTests
{
    [TestFixture]
    public class ServerCommunicationIntegrationTests
    {
        private static readonly string RequestTemplate = @"GET {0} HTTP/1.1
Host:{1}
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language:en-US,en;q=0.5
Accept-Encoding:gzip, deflate
Connection:keep-alive
Upgrade-Insecure-Requests:1
{2}
";
        private const int port = 5000;

        private IWebHost host;
        private Uri baseUri;

        [OneTimeSetUp]
        public async Task StartUp()
        {
            host = WebHost.CreateDefaultBuilder()
                    .UseStartup<Startup>()
                    .UseKestrel((options) =>
                    {
                        options.ListenLocalhost(port);
                    })
                    .UseHttpSys((options) =>
                    {
                        options.Authentication.Schemes = AuthenticationSchemes.NTLM | AuthenticationSchemes.Negotiate;
                    }).Build();
            await host.StartAsync();
            List<string> addresses = new List<string>(host.ServerFeatures.Get<IServerAddressesFeature>().Addresses);
            string firstAddress = addresses[0];
            baseUri = new Uri(firstAddress);
        }

        [OneTimeTearDown]
        public async Task TearDown()
        {
            await host.StopAsync();
        }

        [Test]
        public async Task TestBasic()
        {
            string authType = BasicGenerator.AuthorizationHeaderMarker;
            string userName = "farnsworth";
            string password = "GoodNewsEveryone!";
            string relativeUri = "/api/auth/basic";
            Uri fullUri = new Uri(baseUri, relativeUri);
            string initialRequest = CreateInitialRequest(fullUri);
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                await socket.ConnectAsync("localhost", port);
                HttpResponse initialResponse = await SendRequestAndGetResponse(socket, initialRequest);
                Assert.That(initialResponse.StatusCode, Is.EqualTo(401));
                Assert.That(initialResponse.Headers.ContainsKey("WWW-Authenticate"));

                string authHeader = GetDesiredAuthHeader(authType, initialResponse);
                Assert.That(authHeader, Is.Not.Null);

                BasicGenerator generator = new BasicGenerator(userName, password);
                string authorizeRequest = CreateRequest(fullUri, generator.GenerateAuthorizationHeader());
                HttpResponse authorizedResponse = await SendRequestAndGetResponse(socket, authorizeRequest);
                Assert.That(authorizedResponse.StatusCode, Is.EqualTo(200));
                socket.Close();
            }
        }

        [Test]
        public async Task TestDigest()
        {
            string authType = DigestGenerator.AuthorizationHeaderMarker;
            string userName = "leela";
            string password = "Nibbler";
            string relativeUri = "/api/auth/digest";
            Uri fullUri = new Uri(baseUri, relativeUri);
            string initialRequest = CreateInitialRequest(fullUri);
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                socket.Connect("localhost", port);
                HttpResponse initialResponse = await SendRequestAndGetResponse(socket, initialRequest);
                Assert.That(initialResponse.StatusCode, Is.EqualTo(401));
                Assert.That(initialResponse.Headers.ContainsKey("WWW-Authenticate"));

                string authHeader = GetDesiredAuthHeader(authType, initialResponse);
                Assert.That(authHeader, Is.Not.Null);

                DigestGenerator generator = new DigestGenerator(userName, password, "GET", relativeUri, authHeader);
                string authorizeRequest = CreateRequest(fullUri, generator.GenerateAuthorizationHeader());
                HttpResponse authorizedResponse = await SendRequestAndGetResponse(socket, authorizeRequest);
                Assert.That(authorizedResponse.StatusCode, Is.EqualTo(200));
                socket.Close();
            }
        }

        [Test]
        public async Task TestNtlm()
        {
            string authType = NtlmGenerator.AuthorizationHeaderMarker;
            string userName = "PassedBallAuthUser";
            string password = "PassedBallP@ssw0rd!";
            string relativeUri = "/api/auth/ntlm";
            Uri fullUri = new Uri(baseUri, relativeUri);
            string initialRequest = CreateInitialRequest(fullUri);
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                socket.Connect("localhost", port);
                HttpResponse initialResponse = await SendRequestAndGetResponse(socket, initialRequest);
                Assert.That(initialResponse.StatusCode, Is.EqualTo(401));
                Assert.That(initialResponse.Headers.ContainsKey("WWW-Authenticate"));

                string authHeader = GetDesiredAuthHeader(authType, initialResponse);
                Assert.That(authHeader, Is.Not.Null);

                NtlmNegotiateMessageGenerator type1Generator = new NtlmNegotiateMessageGenerator();
                string negotioateRequest = CreateRequest(fullUri, type1Generator.GenerateAuthorizationHeader());
                HttpResponse challengeResponse = await SendRequestAndGetResponse(socket, negotioateRequest);
                Assert.That(challengeResponse.StatusCode, Is.EqualTo(401));
                Assert.That(challengeResponse.Headers.ContainsKey("WWW-Authenticate"));

                string challengeAuthHeader = GetDesiredAuthHeader(authType, challengeResponse);
                Assert.That(challengeAuthHeader, Is.Not.Null);

                NtlmChallengeMessageGenerator type2Generator = new NtlmChallengeMessageGenerator(challengeAuthHeader);
                NtlmAuthenticateMessageGenerator type3Generator = new NtlmAuthenticateMessageGenerator(null, null, userName, password, type2Generator);

                string authorizeRequest = CreateRequest(fullUri, type3Generator.GenerateAuthorizationHeader());
                HttpResponse authorizedResponse = await SendRequestAndGetResponse(socket, authorizeRequest);
                Assert.That(authorizedResponse.StatusCode, Is.EqualTo(200));
                socket.Close();
            }
        }

        private string GetDesiredAuthHeader(string authType, HttpResponse response)
        {
            string[] authMethods = response.Headers["WWW-Authenticate"].Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string authMethod in authMethods)
            {
                if (authMethod.StartsWith(authType))
                {
                    return authMethod;
                }
            }

            return null;
        }

        private string CreateRequest(Uri parsedUri, string authHeaderValue)
        {
            string host = parsedUri.Host;
            if (!parsedUri.IsDefaultPort)
            {
                host = string.Format("{0}:{1}", host, parsedUri.Port);
            }

            string actualAuthHeader = string.Empty;
            if (!string.IsNullOrEmpty(authHeaderValue))
            {
                actualAuthHeader = string.Format("Authorization: {0}{1}", authHeaderValue, "\r\n");
            }

            return string.Format(RequestTemplate, parsedUri.ToString(), host, actualAuthHeader);
        }

        private string CreateInitialRequest(Uri url)
        {
            return CreateRequest(url, string.Empty);
        }

        private async Task<HttpResponse> SendRequestAndGetResponse(Socket socket, string requestString)
        {
            NetworkStream authStream = new NetworkStream(socket, false);
            StreamWriter writer = new StreamWriter(authStream);
            await writer.WriteAsync(requestString);
            await writer.FlushAsync();

            List<char> totalResponse = new List<char>();
            bool continueReading = true;
            int bufferSize = 8192;
            int totalBytes = 0;
            StreamReader reader = new StreamReader(authStream);
            while (continueReading)
            {
                char[] buffer = new char[bufferSize];
                int bytesRead = await reader.ReadAsync(buffer, 0, bufferSize);
                if (bytesRead >= 0)
                {
                    totalResponse.AddRange(buffer);
                    totalBytes += bytesRead;
                }

                if (bytesRead < bufferSize)
                {
                    continueReading = false;
                }
            }

            string response = new string(totalResponse.ToArray(), 0, totalBytes);
            return new HttpResponse(response);
        }
    }
}
