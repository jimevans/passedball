using System;

namespace PassedBall
{
    /// <summary>
    /// Generates an NTLM authentication Challenge (or Type 2) message. This message
    /// type is returned as a challenge from the server after the server receives an
    /// NTLM negotiate (or Type 1) message.
    /// </summary>
    public class NtlmChallengeMessageGenerator : NtlmGenerator
    {
        private readonly byte[] challenge;
        private readonly string target;
        private readonly byte[] targetInfo;
        private readonly NtlmNegotiateFlags flags;

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmChallengeMessageGenerator"/> class,
        /// representing an NTLM authentication Challenge (or Type 2) message
        /// </summary>
        /// <param name="messageBody">The message body as a base64-encoded string.</param>
        public NtlmChallengeMessageGenerator(string messageBody)
            : this(Convert.FromBase64String(messageBody))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmChallengeMessageGenerator"/> class,
        /// representing an NTLM authentication Challenge (or Type 2) message
        /// </summary>
        /// <param name="message">The message body as an array of bytes.</param>
        public NtlmChallengeMessageGenerator(byte[] message)
            : base(message, NtlmMessageType.Challenge)
        {
            // Type 2 message is laid out as follows:
            // First 8 bytes: NTLMSSP[0]
            // Next 4 bytes: Ulong, value 2
            // Next 8 bytes, starting at offset 12: target field (2 ushort lengths, 1 ulong offset)
            // Next 4 bytes, starting at offset 20: Flags, e.g. 0x22890235
            // Next 8 bytes, starting at offset 24: Challenge
            // Next 8 bytes, starting at offset 32: ??? (8 bytes of zeros)
            // Next 8 bytes, starting at offset 40: targetinfo field (2 ushort lengths, 1 ulong offset)
            // Next 2 bytes, major/minor version number (e.g. 0x05 0x02)
            // Next 8 bytes, build number
            // Next 2 bytes, protocol version number (e.g. 0x00 0x0f)
            // Next, various text fields, and a ushort of value 0 at the end

            // Parse out the rest of the info we need from the message
            // The nonce is the 8 bytes starting from the byte in position 24.
            challenge = ReadBytes(24, 8);

            flags = (NtlmNegotiateFlags)ReadUInt(20);

            // Do the target!
            target = null;
            // The TARGET_DESIRED flag is said to not have understood semantics
            // in Type2 messages, so use the length of the packet to decide
            // how to proceed instead
            if (MessageLength >= 12 + 8)
            {
                byte[] bytes = ReadSecurityBuffer(12);
                if (bytes.Length != 0)
                {
                    target = GetCharset(flags).GetString(bytes);
                }
            }

            // Do the target info!
            targetInfo = null;
            // TARGET_DESIRED flag cannot be relied on, so use packet length
            if (MessageLength >= 40 + 8)
            {
                byte[] bytes = ReadSecurityBuffer(40);
                if (bytes.Length != 0)
                {
                    targetInfo = bytes;
                }
            }
        }

        /// <summary>
        /// Gets the challenge portion of the server challenge message as an array of bytes.
        /// </summary>
        public byte[] Challenge
        {
            get { return challenge; }
        }

        /// <summary>
        /// Gets the target of the server challenge message.
        /// </summary>
        public string Target
        {
            get { return target; }
        }

        /// <summary>
        /// Gets the target info portion of the server challenge message as an array of bytes.
        /// </summary>
        public byte[] TargetInfo
        {
            get { return targetInfo; }
        }

        /// <summary>
        /// Gets the <see cref="NtlmNegotiateFlags"/> values returned by the server challenge.
        /// </summary>
        public NtlmNegotiateFlags Flags
        {
            get { return flags; }
        }

        /// <summary>
        /// Creates the NTLM challenge (Type 2) message.
        /// </summary>
        protected override void BuildMessage()
        {
            // Building the Type 2 message is a no-op.
        }
    }
}
