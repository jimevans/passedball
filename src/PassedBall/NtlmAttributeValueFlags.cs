using System;

namespace PassedBall
{
    /// <summary>
    /// Attribute value flags used to indiciate a client or server configuration
    /// </summary>
    [Flags]
    public enum NtlmAttributeValueFlags
    {
        /// <summary>
        /// Indicates to the client that the account authentication is constrained.
        /// </summary>
        AuthenticationConstrained = 0x00000001,

        /// <summary>
        /// Indicates that the client is providing message integrity in the MIC
        /// field in the AUTHENTICATE_MESSAGE.
        /// </summary>
        ClientProvidesMessageIntegrity = 0x00000002,

        /// <summary>
        /// Indicates that the client is providing a target SPN generated from an untrusted source.
        /// </summary>
        UntrustedTargetSpn = 0x00000004,
    }
}
