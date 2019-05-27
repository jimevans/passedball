using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PassedBall
{
    /// <summary>
    /// Represents a class that is able to generate an Authorization header
    /// for HTTP Digest authentication.
    /// </summary>
    public class DigestGenerator : AuthorizationHeaderGenerator
    {
        private const string DigestAuthenticationMarker = "Digest";

        private readonly DigestQualityOfProtection qop = DigestQualityOfProtection.Unknown;
        private readonly string userName;
        private readonly string password;
        private readonly string realm;
        private readonly string nonce;
        private readonly string algorithm;
        private readonly string httpMethod;
        private readonly string url;
        private readonly string opaque;
        private readonly bool isStale;
        private string cnonce;
        private int nonceCount;

        /// <summary>
        /// Initializes a new instance of the <see cref="DigestGenerator"/> class.
        /// </summary>
        /// <param name="userName">The user name used to authenticate.</param>
        /// <param name="password">The password used to authenticate.</param>
        /// <param name="httpMethod">The HTTP method (GET, POST, etc.) used to access the protected resource.</param>
        /// <param name="url">The URL of the protected resource.</param>
        /// <param name="authenticationHeaderValue">The value of the server's WWW-Authenticate header.</param>
        public DigestGenerator(string userName, string password, string httpMethod, string url, string authenticationHeaderValue)
            : this(userName, password, httpMethod, url, null, 0, authenticationHeaderValue)
        {
            if (this.cnonce == null)
            {
                CreateClientNonce();
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DigestGenerator"/> class.
        /// </summary>
        /// <param name="userName">The user name used to authenticate.</param>
        /// <param name="password">The password used to authenticate.</param>
        /// <param name="httpMethod">The HTTP method (GET, POST, etc.) used to access the protected resource.</param>
        /// <param name="url">The URL of the protected resource.</param>
        /// <param name="clientNonce">The eight-byte client nonce value generated for use with multiple calls.</param>
        /// <param name="nonceCount">The count of times the nonce has been used.</param>
        /// <param name="authenticationHeaderValue">The value of the server's WWW-Authenticate header.</param>
        public DigestGenerator(string userName, string password, string httpMethod, string url, string clientNonce, int nonceCount, string authenticationHeaderValue)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException("userName", "userName may not be null or the empty string");
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password", "password may not be null or the empty string");
            }

            if (string.IsNullOrEmpty(httpMethod))
            {
                throw new ArgumentNullException("httpMethod", "httpMethod may not be null or the empty string");
            }

            if (string.IsNullOrEmpty(url))
            {
                throw new ArgumentNullException("url", "url may not be null or the empty string");
            }

            if (string.IsNullOrEmpty(authenticationHeaderValue))
            {
                throw new ArgumentNullException("authenticationHeaderValue", "authenticationHeaderValue may not be null or the empty string");
            }

            this.userName = userName;
            this.password = password;
            this.httpMethod = httpMethod;
            this.url = url;

            Dictionary<string, string> digestAuthAttributes = ParseHeaderValue(authenticationHeaderValue);

            if (!digestAuthAttributes.ContainsKey("realm"))
            {
                throw new ArgumentException("WWW-Authenticate header value must contain realm token for Digest authentication", "authenticationHeaderValue");
            }

            if (!digestAuthAttributes.ContainsKey("nonce"))
            {
                throw new ArgumentException("WWW-Authenticate header value must contain nonce token for Digest authentication", "authenticationHeaderValue");
            }

            this.realm = digestAuthAttributes["realm"];
            this.nonce = digestAuthAttributes["nonce"];

            this.algorithm = string.Empty;
            if (digestAuthAttributes.ContainsKey("algorithm"))
            {
                this.algorithm = digestAuthAttributes["algorithm"];
                if (this.algorithm != "MD5" && this.algorithm != "MD5-sess")
                {
                    throw new ArgumentException("Unknown algorithm in WWW-Authenticate header: " + this.algorithm, "authenticationHeaderValue");
                }
            }
            else
            {
                this.algorithm = "MD5";
            }

            if (digestAuthAttributes.ContainsKey("qop"))
            {
                string qopStringValue = digestAuthAttributes["qop"];
                if (qopStringValue.Contains("auth-int") && qopStringValue.Contains("auth"))
                {
                    // If the qop value contains both, fall back to auth.
                    this.qop = DigestQualityOfProtection.Authentication;
                }
                else if (qopStringValue == "auth" || qopStringValue == "auth-int")
                {
                    if (qopStringValue == "auth")
                    {
                        this.qop = DigestQualityOfProtection.Authentication;
                    }
                    else
                    {
                        this.qop = DigestQualityOfProtection.AuthenticationWithIntegrity;
                    }
                }
                else
                {
                    throw new ArgumentException("Unknown qop value in WWW-Authenticate header: " + qopStringValue, "authenticationHeaderValue");
                }
            }

            this.opaque = string.Empty;
            if (digestAuthAttributes.ContainsKey("opaque"))
            {
                this.opaque = digestAuthAttributes["opaque"];
            }

            this.isStale = false;
            if (digestAuthAttributes.ContainsKey("stale"))
            {
                this.isStale = bool.Parse(digestAuthAttributes["stale"].ToLowerInvariant());
            }

            this.Domain = string.Empty;
            if (digestAuthAttributes.ContainsKey("domain"))
            {
                this.Domain = digestAuthAttributes["domain"];
            }

            if (this.isStale)
            {
                CreateClientNonce();
            }
            else
            {
                this.cnonce = clientNonce;
            }
            
            this.nonceCount = nonceCount;
        }

        /// <summary>
        /// Gets the value of the Digest authentication header marker type ("Digest").
        /// </summary>
        public static string AuthorizationHeaderMarker => DigestAuthenticationMarker;

        /// <summary>
        /// Gets the string value indicating Digest HTTP authentication.
        /// </summary>
        public override string AuthenticationType => DigestAuthenticationMarker;

        /// <summary>
        /// Gets the list of domains for which the same authentication response is valid.
        /// </summary>
        public string Domain { get; private set; }

        /// <summary>
        /// Gets the value for the response portion of the authorization header
        /// for Digest authentication as an array of bytes.
        /// </summary>
        /// <returns>
        /// The response portion of the authorization header value for
        /// Digest authentication as an array of bytes.
        /// </returns>
        public override byte[] GetAuthorizationBytes()
        {
            string initialAuth = string.Format("{0}:{1}:{2}", userName, realm, password);
            byte[] initialAuthBytes = Encoding.UTF8.GetBytes(initialAuth);

            byte[] ha1;
            if (algorithm == "MD5-sess")
            {
                byte[] initialAuthHash;
                using (var md5 = MD5.Create())
                {
                    initialAuthHash = md5.ComputeHash(initialAuthBytes);
                }

                string initialAuthChecksum = FormatByteArrayAsHexString(initialAuthHash);

                string source = string.Format("{0}:{1}:{2}", initialAuthChecksum, nonce, cnonce);
                ha1 = Encoding.UTF8.GetBytes(source);
            }
            else
            {
                ha1 = new byte[initialAuthBytes.Length];
                Array.Copy(initialAuthBytes, ha1, initialAuthBytes.Length);
            }

            byte[] ha1Hash;
            using (var md5 = MD5.Create())
            {
                ha1Hash = md5.ComputeHash(ha1);
            }

            string ha1String = FormatByteArrayAsHexString(ha1Hash);

            byte[] ha2;
            string httpMethod = this.httpMethod;
            string requestUri = this.url;
            if (qop == DigestQualityOfProtection.AuthenticationWithIntegrity)
            {
                // TODO: Include content
                // string body;
                // byte[] bodyBytes;
                // using (var md5 = MD5.Create())
                // {
                //     bodyBytes = md5.ComputeHash(charset.GetBytes(body));
                // }
                // string source = string.Format("{0}:{1}:{2}", httpMethod, uri, HashToString(bodyBytes));
                throw new NotImplementedException("Digest authentication using the auth-int quality of protection (qop) parameter is not yet implemented.");
            }
            else
            {
                string source = string.Format("{0}:{1}", httpMethod, requestUri);
                ha2 = Encoding.UTF8.GetBytes(source);
            }

            byte[] ha2Hash;
            using (var md5 = MD5.Create())
            {
                ha2Hash = md5.ComputeHash(ha2);
            }

            string ha2String = FormatByteArrayAsHexString(ha2Hash);

            string responseString;
            if (qop != DigestQualityOfProtection.Unspecified)
            {
                string qopString = "auth";
                if (qop == DigestQualityOfProtection.AuthenticationWithIntegrity)
                {
                    qopString = "auth-int";
                }

                responseString = string.Format("{0}:{1}:{2:x8}:{3}:{4}:{5}", ha1String, nonce, nonceCount, cnonce, qopString, ha2String);
            }
            else
            {
                responseString = string.Format("{0}:{1}:{2}", ha1String, nonce, ha2String);
            }

            byte[] responseBytes;
            using (var md5 = MD5.Create())
            {
                responseBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(responseString));
            }

            return responseBytes;
        }

        /// <summary>
        /// Gets the value for the response portion of the authorization header
        /// for Digest authentication as hexadecimal formatted string.
        /// </summary>
        /// <returns>
        /// The response portion of the authorization header value for
        /// Digest authentication as a hexadecimal formatted string.
        /// </returns>
        public override string GetAuthorizationValue()
        {
            string responseString = FormatByteArrayAsHexString(GetAuthorizationBytes());
            return responseString;
        }

        /// <summary>
        /// Gets the full value for the HTTP Digest authentication Authorization header, including the
        /// authentication type.
        /// </summary>
        /// <returns>The full value for the HTTP Digest authentication Authorization header.</returns>
        public override string GenerateAuthorizationHeader()
        {
            StringBuilder headerBuilder = new StringBuilder();
            headerBuilder.AppendFormat("username=\"{0}\"", userName);
            headerBuilder.AppendFormat(", realm=\"{0}\"", realm);
            headerBuilder.AppendFormat(", nonce=\"{0}\"", nonce);
            headerBuilder.AppendFormat(", uri=\"{0}\"", url);
            headerBuilder.AppendFormat(", response=\"{0}\"", GetAuthorizationValue());
            if (qop != DigestQualityOfProtection.Unspecified)
            {
                string qpopString = "auth";
                if (qop == DigestQualityOfProtection.AuthenticationWithIntegrity)
                {
                    qpopString = "auth-int";
                }

                headerBuilder.AppendFormat(", qop={0}", qpopString);
                headerBuilder.AppendFormat(", nc={0:x8}", nonceCount);
                headerBuilder.AppendFormat(", cnonce=\"{0}\"", cnonce);
            }

            if (!string.IsNullOrEmpty(algorithm))
            {
                headerBuilder.AppendFormat(", algorithm={0}", algorithm);
            }

            if (!string.IsNullOrEmpty(opaque))
            {
                headerBuilder.AppendFormat(", opaque=\"{0}\"", opaque);
            }

            return string.Format("{0} {1}", AuthenticationType, headerBuilder.ToString());
        }

        private Dictionary<string, string> ParseHeaderValue(string authenticationHeaderValue)
        {
            string parsedHeaderValue = authenticationHeaderValue;
            if (parsedHeaderValue.StartsWith(this.AuthenticationType) && parsedHeaderValue.Length >= this.AuthenticationType.Length + 1)
            {
                parsedHeaderValue = parsedHeaderValue.Substring(this.AuthenticationType.Length + 1);
            }

            // Use a Regex to split the header value to allow for comma-
            // delimited values inside double-quoted token values.
            string[] contentAttributes = Regex.Split(parsedHeaderValue, ",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))");
            Dictionary<string, string> digestAuthAttributes = new Dictionary<string, string>();
            foreach (string contentAttribute in contentAttributes)
            {
                string[] attributeKeyValuePair = contentAttribute.Split(new char[] { '=' }, 2);
                if (attributeKeyValuePair.Length > 1)
                {
                    string name = attributeKeyValuePair[0].Trim();
                    string value = attributeKeyValuePair[1].Trim();
                    if (value[0] == '\"' && value[value.Length - 1] == '\"')
                    {
                        value = value.Substring(1, value.Length - 2);
                    }

                    digestAuthAttributes[name] = value;
                }
            }

            return digestAuthAttributes;
        }

        private static string FormatByteArrayAsHexString(byte[] hash)
        {
            StringBuilder builder = new StringBuilder();
            foreach (byte currentByte in hash)
            {
                builder.AppendFormat("{0:x2}", currentByte);
            }

            return builder.ToString();
        }

        private void CreateClientNonce()
        {
            Random random = new Random();
            byte[] rval = new byte[8];
            random.NextBytes(rval);
            this.cnonce = FormatByteArrayAsHexString(rval);
            this.nonceCount = 1;
        }
    }
}
