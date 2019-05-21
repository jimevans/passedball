namespace PassedBall
{
    /// <summary>
    /// Represents the possible values for HTTP Digest authentication's
    /// Quality of Protection (qop) attribute.
    /// </summary>
    public enum DigestQualityOfProtection
    {
        /// <summary>
        /// The qop attribute is an unknown value.
        /// </summary>
        Unknown = -1,

        /// <summary>
        /// The qop value is unspecified by the server.
        /// </summary>
        Unspecified = 0,

        /// <summary>
        /// The qop value is specified as authentication using integrity ("auth-int").
        /// </summary>
        AuthenticationWithIntegrity = 1,

        /// <summary>
        /// The qop value is specified as authentication only ("auth").
        /// </summary>
        Authentication = 2,
    }
}
