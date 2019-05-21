namespace PassedBall
{
    /// <summary>
    /// Represents a class that is able to generate an Authorization header
    /// for a given type of authentication.
    /// </summary>
    public abstract class AuthorizationHeaderGenerator
    {
        /// <summary>
        /// Gets the string value indicating the type of authentication
        /// requested in the response to an unauthorized request for a
        /// resource.
        /// </summary>
        public abstract string AuthenticationType { get; }

        /// <summary>
        /// Gets the value for the authorization header as an array of bytes.
        /// </summary>
        /// <returns>The authorization header value as an array of bytes.</returns>
        public abstract byte[] GetAuthorizationBytes();

        /// <summary>
        /// Gets the value for the authorization header as an appropriately encoded string.
        /// </summary>
        /// <returns>The authorization header value as an appropriately encoded string.</returns>
        public abstract string GetAuthorizationValue();

        /// <summary>
        /// Gets the full value for the HTTP Authorization header, including the
        /// authentication type.
        /// </summary>
        /// <returns>The full value for the HTTP Authorization header, including the authentication type.</returns>
        /// <remarks>
        /// A typical Authorization header requires the authentication type, along with
        /// the appropriately encoded value. For example, for a basic authentication type,
        /// using a user name of "Aladdin" and a password of "open sesame", header would
        /// look like:
        /// <code>
        /// Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        /// </code>
        /// </remarks>
        public virtual string GenerateAuthorizationHeader()
        {
            return string.Format("{0} {1}", AuthenticationType, GetAuthorizationValue());
        }
    }
}
