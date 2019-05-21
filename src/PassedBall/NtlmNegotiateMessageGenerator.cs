using System;
using System.Text;

namespace PassedBall
{
    /// <summary>
    /// Generates an NTLM authentication Negotiate (or Type 1) message. This message
    /// type is the intiation of an NTLM authentication handshake with a server supporting
    /// NTLM authentication.
    /// </summary>
    public class NtlmNegotiateMessageGenerator : NtlmGenerator
    {
        private readonly byte[] hostBytes = null;
        private readonly byte[] domainBytes = null;
        private readonly NtlmNegotiateFlags flags;

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmNegotiateMessageGenerator"/> class.
        /// </summary>
        public NtlmNegotiateMessageGenerator()
            : this(null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmNegotiateMessageGenerator"/> class
        /// for the specified domain and host.
        /// </summary>
        /// <param name="domain">The domain to negotiate authentication for.</param>
        /// <param name="host">The host to negotiate authentication for.</param>
        public NtlmNegotiateMessageGenerator(string domain, string host)
            : this(domain, host, GetDefaultFlags())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmNegotiateMessageGenerator"/> class
        /// for the specified domain and host, using the specified connection options.
        /// </summary>
        /// <param name="domain">The domain to negotiate authentication for.</param>
        /// <param name="host">The host to negotiate authentication for.</param>
        /// <param name="flags">The <see cref="NtlmNegotiateFlags"/> value containing authentication options to be negotiated with the server.</param>
        public NtlmNegotiateMessageGenerator(string domain, string host, NtlmNegotiateFlags flags)
            : base()
        {
            this.flags = flags;

            // Strip off domain name from the host!
            // Domain supplied only using OEM (ASCII) encoding.
            string unqualifiedHost = ConvertHost(host);
            if (unqualifiedHost != null)
            {
                hostBytes = Encoding.ASCII.GetBytes(unqualifiedHost);
            }

            // Use only the base domain name!
            // Host supplied only using OEM (ASCII) encoding.
            string unqualifiedDomain = ConvertDomain(domain);
            if (unqualifiedDomain != null)
            {
                domainBytes = Encoding.ASCII.GetBytes(unqualifiedDomain.ToUpperInvariant());
            }
        }

        /// <summary>
        /// Creates the NTLM negotiate (Type 1) message.
        /// </summary>
        protected override void BuildMessage()
        {
            int initialLength = SignatureLength + MessageTypeLength + FlagsLength + SecurityBufferLength * 2 + VersionLength;

            int domainBytesLength = 0;
            if (domainBytes != null)
            {
                domainBytesLength = domainBytes.Length;
            }

            int hostBytesLength = 0;
            if (hostBytes != null)
            {
                hostBytesLength = hostBytes.Length;
            }

            // Now, build the message. Calculate its length first, including
            // signature or type.
            int finalLength = initialLength + hostBytesLength + domainBytesLength;

            // Set up the response. This will initialize the signature, message
            // type, and flags.
            InitializeMessage(finalLength, NtlmMessageType.Negotiate);

            // Flags. These are the complete set of flags we support.
            AddUInt((uint)flags);

            // Domain length (two times).
            AddUShort(domainBytesLength);
            AddUShort(domainBytesLength);

            // Domain offset.
            AddUInt(Convert.ToUInt32(hostBytesLength + initialLength));

            // Host length (two times).
            AddUShort(hostBytesLength);
            AddUShort(hostBytesLength);

            // Host offset (always 32 + 8).
            AddUInt(Convert.ToUInt32(initialLength));

            // Add version (for debugging purposes)
            NtlmVersion version = new NtlmVersion(5, 1, 2600);
            AddBytes(version.AsBytes());

            // Host (workstation) String.
            if (hostBytes != null)
            {
                AddBytes(hostBytes);
            }

            // Domain String.
            if (domainBytes != null)
            {
                AddBytes(domainBytes);
            }
        }

        private static NtlmNegotiateFlags GetDefaultFlags()
        {
            NtlmNegotiateFlags flags = NtlmNegotiateFlags.RequestNtlmV1 |
                                       NtlmNegotiateFlags.RequestNtlmV2Session |
                                       NtlmNegotiateFlags.RequestVersion |
                                       NtlmNegotiateFlags.AlwaysSign |
                                       NtlmNegotiateFlags.Request128BitEncryption |
                                       NtlmNegotiateFlags.Request56BitEncryption |
                                       NtlmNegotiateFlags.RequestUnicodeEncoding;
            return flags;
        }
    }
}
