using System;

namespace PassedBall
{
    /// <summary>
    /// Flags used in negotiating the type of connection for NTLM authentication.
    /// </summary>
    /// <remarks>
    /// Missing values are bits in the flag set that must be zero as defined by
    /// the protocol documented in section 2.2.2.5 of the Microsoft NT Lan Manager
    /// (NTLM) Authentication Protocol (MS-NLMP). At the time of this writing,
    /// documentation of the protocol can be found at
    /// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4
    /// </remarks>
    [Flags]
    public enum NtlmNegotiateFlags : uint
    {
        /// <summary>
        /// Requests Unicode character set encoding.
        /// </summary>
        RequestUnicodeEncoding = 0x00000001,

        /// <summary>
        /// Requests OEM character set encoding.
        /// </summary>
        RequestOemEncoding = 0x00000002,

        /// <summary>
        /// Indicates a target name field of the challenge message must be supplied.
        /// </summary>
        RequestTarget = 0x00000004,

        /// <summary>
        /// Requests session key negotiation for message signatures.
        /// </summary>
        RequestSign = 0x00000010,

        /// <summary>
        /// Requests session key negotiation for message confidentiality.
        /// </summary>
        RequestSeal = 0x00000020,

        /// <summary>
        /// Requests connectionless authentication.
        /// </summary>
        RequestDatagram = 0x00000040,

        /// <summary>
        /// Requests Lan Manager (LM) session key computation.
        /// </summary>
        RequestLanManagerKey = 0x00000080,

        /// <summary>
        /// Requests usage of the NTLM v1 session security protocol.
        /// </summary>
        RequestNtlmV1 = 0x00000200,

        /// <summary>
        /// Requests an anonymous connection.
        /// </summary>
        UseAnonymousConnection = 0x00000800,

        /// <summary>
        /// Indicates that the Domain field is populated.
        /// </summary>
        OemDomainSupplied = 0x00001000,

        /// <summary>
        /// Indicates that the Workstation field is populated.
        /// </summary>
        OemWorkstationSupplied = 0x00002000,

        /// <summary>
        /// Requests the presence of a signature block on all messages.
        /// </summary>
        AlwaysSign = 0x00008000,

        /// <summary>
        /// Indicates the target type must be a domain name.
        /// </summary>
        TargetTypeDomain = 0x00010000,

        /// <summary>
        /// Indicates the target type must be a server name.
        /// </summary>
        TargetTypeServer = 0x00020000,

        /// <summary>
        /// Requests the usage of NTLM v2 session security.
        /// </summary>
        RequestNtlmV2Session = 0x00080000,

        /// <summary>
        /// Requests an identify level token.
        /// </summary>
        RequestIdentifyLevelToken = 0x00100000,

        /// <summary>
        /// Requests usage of a specific one-way function to generate a key based on the user's password.
        /// </summary>
        RequestNonNTSessionKey = 0x00400000,

        /// <summary>
        /// Requests that the TargetInfo fields be populated in the challenge message.
        /// </summary>
        RequestTargetInfo = 0x00800000,

        /// <summary>
        /// Requests the protocol version number.
        /// </summary>
        RequestVersion = 0x02000000,

        /// <summary>
        /// Requests 128-bit encryption for session keys.
        /// </summary>
        Request128BitEncryption = 0x20000000,

        /// <summary>
        /// Requests an explicit key exchange with the server.
        /// </summary>
        RequestKeyExchange = 0x40000000,

        /// <summary>
        /// Requests 56-bit encryption for sealed or signed messages.
        /// </summary>
        Request56BitEncryption = 0x80000000,
    }
}
