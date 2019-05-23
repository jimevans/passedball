using System;
using System.Collections.Generic;
using System.Text;

namespace PassedBall
{
    /// <summary>
    /// Represents a class that is able to generate an Authorization header
    /// for HTTP Basic authentication.
    /// </summary>
    public class BasicGenerator : AuthorizationHeaderGenerator
    {
        private const string BasicAuthenticationMarker = "Basic";

        private readonly string userName;
        private readonly string password;
        private readonly Encoding encoding = Encoding.ASCII;

        /// <summary>
        /// Initializes a new instance of the <see cref="BasicGenerator"/> class.
        /// </summary>
        /// <param name="userName">The user name used to authenticate.</param>
        /// <param name="password">The password used to authenticate.</param>
        public BasicGenerator(string userName, string password) 
            : this(userName, password, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BasicGenerator"/> class.
        /// </summary>
        /// <param name="userName">The user name used to authenticate.</param>
        /// <param name="password">The password used to authenticate.</param>
        /// <param name="authenticationHeaderValue">The value of the server's WWW-Authenticate header.</param>
        public BasicGenerator(string userName, string password, string authenticationHeaderValue)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException("userName", "userName may not be null or the empty string");
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password", "password may not be null or the empty string");
            }

            this.userName = userName;
            this.password = password;
            if (!string.IsNullOrEmpty(authenticationHeaderValue))
            {
                string[] contentAttributes = authenticationHeaderValue.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                Dictionary<string, string> authAttributes = new Dictionary<string, string>();
                foreach (string contentAttribute in contentAttributes)
                {
                    string[] attributeKeyValuePair = contentAttribute.Split('=');
                    if (attributeKeyValuePair.Length > 1)
                    {
                        string name = attributeKeyValuePair[0].Trim();
                        string value = attributeKeyValuePair[1].Trim();
                        if (value[0] == '\"' && value[value.Length - 1] == '\"')
                        {
                            value = value.Substring(1, value.Length - 2);
                        }

                        authAttributes[name] = value;
                    }
                }

                if (authAttributes.ContainsKey("realm"))
                {
                    Realm = authAttributes["realm"];
                }

                if (authAttributes.ContainsKey("charset"))
                {
                    // TODO: Add more dynamic creation of more charset types.
                    string charset = authAttributes["charset"];
                    if (charset.ToLowerInvariant() == "utf-8" || charset.ToLowerInvariant() == "utf8")
                    {
                        encoding = Encoding.UTF8;
                    }
                }
            }
        }

        /// <summary>
        /// Gets the string value indicating Basic HTTP authentication.
        /// </summary>
        public override string AuthenticationType => BasicAuthenticationMarker;

        /// <summary>
        /// Gets the value of the "realm" issued in the authentication challenge, if any.
        /// </summary>
        public string Realm { get; private set; } = string.Empty;

        /// <summary>
        /// Gets the value for the authorization header for Basic authentication
        /// as an array of bytes.
        /// </summary>
        /// <returns>The authorization header value for Basic authentication as an array of bytes.</returns>
        public override byte[] GetAuthorizationBytes()
        {
            string headerValue = string.Format("{0}:{1}", userName, password);
            return encoding.GetBytes(headerValue);
        }

        /// <summary>
        /// Gets the value for the authorization header for Basic authentication
        /// as a base64-encoded string.
        /// </summary>
        /// <returns>The authorization header value as a base64-encoded string.</returns>
        public override string GetAuthorizationValue()
        {
            return Convert.ToBase64String(GetAuthorizationBytes());
        }
    }
}
