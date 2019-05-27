using System;
using System.Text;

namespace PassedBall
{
    /// <summary>
    /// The abstract base class that is able to generate messages required to
    /// create a correct Authorization header for NTLM authentication.
    /// </summary>
    public abstract class NtlmGenerator : AuthorizationHeaderGenerator
    {
        protected const int SignatureLength = 8;
        protected const int MessageTypeLength = 4;
        protected const int FlagsLength = 4;
        protected const int SecurityBufferLength = 8;
        protected const int VersionLength = 8;

        private const string NtlmAuthenticationMarker = "NTLM";

        // The signature string as bytes in the default encoding
        private readonly byte[] MessageSignature = Encoding.ASCII.GetBytes("NTLMSSP\0");

        // The current response
        private byte[] messageContents = null;

        // The current output position
        private int currentOutputPosition = 0;

        /// <summary>
        /// Prevents a default instance of the <see cref="NtlmGenerator"/> abstract base class.
        /// </summary>
        protected NtlmGenerator()
        {
        }

        /// <summary>
        /// Prevents a default instance of the <see cref="NtlmGenerator"/> abstract base class.
        /// </summary>
        /// <param name="messageBody">The message body to parse as a base64-encoded string.</param>
        /// <param name="expectedType">The type of the message being generated.</param>
        protected NtlmGenerator(string messageBody, NtlmMessageType expectedType) :
            this(Convert.FromBase64String(messageBody), expectedType)
        {
        }

        /// <summary>
        /// Prevents a default instance of the <see cref="NtlmGenerator"/> abstract base class.
        /// </summary>
        /// <param name="message">The message body to parse as an array of bytes.</param>
        /// <param name="expectedType">The type of the message being generated.</param>
        protected NtlmGenerator(byte[] message, NtlmMessageType expectedType)
        {
            messageContents = message;

            // Look for NTLM message
            if (messageContents.Length < MessageSignature.Length)
            {
                throw new NtlmAuthorizationGenerationException("NTLM message decoding error - packet too short");
            }

            int i = 0;
            while (i < MessageSignature.Length)
            {
                if (messageContents[i] != MessageSignature[i])
                {
                    throw new NtlmAuthorizationGenerationException("NTLM message expected - instead got unrecognized bytes");
                }

                i++;
            }

            // Check to be sure the correct type is being used.
            NtlmMessageType type = (NtlmMessageType)ReadUInt(MessageSignature.Length);
            if (type != expectedType)
            {
                string errorMessage = string.Format("NTLM type {0} message expected - instead got type {1}", expectedType.ToString(), type.ToString());
                throw new NtlmAuthorizationGenerationException(errorMessage);
            }

            currentOutputPosition = messageContents.Length;
        }

        /// <summary>
        /// Gets the value of the NTLM authentication header marker type ("NTLM").
        /// </summary>
        public static string AuthorizationHeaderMarker => NtlmAuthenticationMarker;

        /// <summary>
        /// Gets the current message contents as an array of bytes.
        /// </summary>
        protected byte[] MessageContents
        {
            get { return messageContents; }
        }

        /// <summary>
        /// Gets or sets the current output position in the current message.
        /// </summary>
        protected int CurrentOutputPosition
        {
            get { return currentOutputPosition; }
            set { currentOutputPosition = value; }
        }

        /// <summary>
        /// Gets the total length of the constructed message.
        /// </summary>
        protected int MessageLength
        {
            get { return currentOutputPosition; }
        }

        /// <summary>
        /// Gets the string value indicating NTLM authentication.
        /// </summary>
        public override string AuthenticationType => NtlmAuthenticationMarker;

        /// <summary>
        /// Gets the value for the authorization header for this NTLM authentication
        /// message as an array of bytes.
        /// </summary>
        /// <returns>The authorization header value for this NTLM authentication message as an array of bytes.</returns>
        public override byte[] GetAuthorizationBytes()
        {
            if (messageContents == null)
            {
                BuildMessage();
            }

            if (messageContents.Length > currentOutputPosition)
            {
                byte[] tmp = new byte[currentOutputPosition];
                Array.Copy(messageContents, 0, tmp, 0, currentOutputPosition);
                messageContents = tmp;
            }

            return messageContents;
        }

        /// <summary>
        /// Gets the value for the authorization header for this NTLM authentication
        /// message as a base64-encoded string.
        /// </summary>
        /// <returns>The authorization header value for this NTLM authentication message as a base64-encoded string.</returns>
        public override string GetAuthorizationValue()
        {
            return Convert.ToBase64String(GetAuthorizationBytes());
        }

        /// <summary>
        /// Creates the NTLM authentication message.
        /// </summary>
        protected abstract void BuildMessage();

        /// <summary>
        /// Reads a specified number of bytes from the generated message 
        /// starting from the specified position.
        /// </summary>
        /// <param name="position">The position at which to start reading the message contents.</param>
        /// <param name="length">The number of bytes to read from the message contents.</param>
        /// <returns>The specified number of bytes from the message contents starting at the specified position.</returns>
        protected byte[] ReadBytes(int position, int length)
        {
            if (messageContents.Length < position + length)
            {
                throw new NtlmAuthorizationGenerationException("NTLM: Message too short");
            }

            byte[] buffer = new byte[length];
            Array.Copy(messageContents, position, buffer, 0, buffer.Length);
            return buffer;
        }

        /// <summary>
        /// Reads an unsigned 16-bit integer from the current message at the specified position.
        /// </summary>
        /// <param name="position">The position from which to read the integer.</param>
        /// <returns>An unsigned 16-bit integer from the current message at the specified position.</returns>
        protected int ReadUShort(int position)
        {
            if (messageContents.Length < position + 2)
            {
                return 0;
            }

            return BitConverter.ToUInt16(messageContents, position);
        }

        /// <summary>
        /// Reads an unsigned 32-bit integer from the current message at the specified position.
        /// </summary>
        /// <param name="position">The position from which to read the integer.</param>
        /// <returns>An unsigned 32-bit integer from the current message at the specified position.</returns>
        protected uint ReadUInt(int position)
        {
            if (messageContents.Length < position + 4)
            {
                return 0;
            }

            return BitConverter.ToUInt32(messageContents, position);
        }

        /// <summary>
        /// Reads a security buffer structure from the current message at the
        /// specified position as an array of bytes.
        /// </summary>
        /// <param name="position">The position from which to read the security buffer.</param>
        /// <returns>
        /// A security buffer structure as an array of bytes from the current message
        /// at the specified position.
        /// </returns>
        /// <remarks>
        /// The security buffer structure is documented in the NTLM authentication
        /// specification, and consists of two 16-bit unsigned integers representing
        /// the length and maximum length of the buffer containing the data and a
        /// 32-bit unsigned integer representing the offset in the message contents
        /// at which to find the data.
        /// </remarks>
        protected byte[] ReadSecurityBuffer(int position)
        {
            int length = ReadUShort(position);
            uint offset = ReadUInt(position + 4);
            if (messageContents.Length < offset + length)
            {
                return new byte[length];
            }

            byte[] buffer = new byte[length];
            Array.Copy(messageContents, offset, buffer, 0, length);
            return buffer;
        }

        /// <summary>
        /// Adds the specified array of bytes to the current position in the message contents.
        /// </summary>
        /// <param name="bytes">The bytes to add to the message contents.</param>
        protected void AddBytes(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return;
            }

            Array.Copy(bytes, 0, messageContents, currentOutputPosition, bytes.Length);
            currentOutputPosition += bytes.Length;
        }

        /// <summary>
        /// Adds the specified value to the current position in the message contents as an unsigned 16-bit integer.
        /// </summary>
        /// <param name="value">The value to add to the message.</param>
        protected void AddUShort(int value)
        {
            AddBytes(BitConverter.GetBytes(Convert.ToUInt16(value)));
        }

        /// <summary>
        /// Adds the specified value to the current position in the message contents as an unsigned 32-bit integer.
        /// </summary>
        /// <param name="value">The value to add to the message.</param>
        protected void AddUInt(uint value)
        {
            AddBytes(BitConverter.GetBytes(value));
        }

        /// <summary>
        /// Initializes the response to contain the message data.
        /// </summary>
        /// <param name="maxlength">The maximum length of the message data.</param>
        /// <param name="messageType">The <see cref="NtlmMessageType"/> of the message.</param>
        protected void InitializeMessage(int maxlength, NtlmMessageType messageType)
        {
            messageContents = new byte[maxlength];
            currentOutputPosition = 0;
            AddBytes(MessageSignature);
            AddUInt(Convert.ToUInt32(messageType));
        }

        /// <summary>
        /// Converts a host name to a standard form.
        /// </summary>
        /// <param name="host">The host name to convert.</param>
        /// <returns>The converted host name.</returns>
        protected string ConvertHost(string host)
        {
            return StripDotSuffix(host);
        }

        /// <summary>
        /// Converts a domain name to a standard form.
        /// </summary>
        /// <param name="domain">The domain name to convert.</param>
        /// <returns>The converted domain name.</returns>
        protected string ConvertDomain(string domain)
        {
            return StripDotSuffix(domain);
        }

        /// <summary>
        /// Gets the character encoding specified by the message flags.
        /// </summary>
        /// <param name="flags">The <see cref="NtlmNegotiateFlags"/> value containing the requested encoding information.</param>
        /// <returns>The <see cref="Encoding"/> object used to encode string values into bytes for the message.</returns>
        protected Encoding GetCharset(NtlmNegotiateFlags flags)
        {
            if ((flags & NtlmNegotiateFlags.RequestUnicodeEncoding) == 0)
            {
                return Encoding.ASCII;
            }

            return Encoding.Unicode;
        }

        ///** Strip dot suffix from a name */
        private string StripDotSuffix(string value)
        {
            if (value == null)
            {
                return null;
            }

            int index = value.IndexOf('.');
            if (index != -1)
            {
                return value.Substring(0, index);
            }

            return value;
        }
    }
}
