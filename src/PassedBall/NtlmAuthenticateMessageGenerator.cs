using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PassedBall
{
    /// <summary>
    /// Generates an NTLM authentication Authenticate (or Type 3) message. This message
    /// type is the final stage in the NTLM authentication handshake and is issued in
    /// response to the server-provided challenge (Type 2) message.
    /// </summary>
    public class NtlmAuthenticateMessageGenerator : NtlmGenerator
    {
        private static readonly Random RandomValueGenerator = new Random();

        // prefix for GSS API channel binding
        private static readonly byte[] MagicTlsServerEndPoint = Encoding.ASCII.GetBytes("tls-server-end-point:");

        // For mic computation
        private readonly byte[] type1Message;
        private readonly byte[] type2Message;

        // Response flags from the type2 message
        private readonly NtlmNegotiateFlags negotiatedOptionFlags;

        private readonly byte[] domainBytes;
        private readonly byte[] hostBytes;
        private readonly byte[] userBytes;

        private readonly byte[] lmResponse;
        private readonly byte[] ntlmResponse;
        private readonly byte[] sessionKey;
        private readonly byte[] exportedSessionKey;

        private readonly bool isMessageIntegrityCodeRequired;

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmAuthenticateMessageGenerator"/> class,
        /// which generates an NTLM authentication Authenticate (or Type 3) message.
        /// </summary>
        /// <param name="domain">The domain against which to authenticate.</param>
        /// <param name="host">The host against which to authenticate.</param>
        /// <param name="user">The user name to use in authenticating.</param>
        /// <param name="password">The password to use in authenticating.</param>
        /// <param name="nonce">The random byte array sent by the server as part of the challenge message.</param>
        /// <param name="negotiatedOptionFlags">The <see cref="NtlmNegotiateFlags"/> sent by the server as part of the challenge message.</param>
        /// <param name="target">The target sent by the server as part of the challenge message.</param>
        /// <param name="targetInformation">The target information structure as an array of bytes sent by the server as part of the challenge message.</param>
        public NtlmAuthenticateMessageGenerator(string domain, string host, string user, string password, byte[] nonce, NtlmNegotiateFlags negotiatedOptionFlags, string target, byte[] targetInformation)
            : this(domain, host, user, password, nonce, negotiatedOptionFlags, target, targetInformation, null, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmAuthenticateMessageGenerator"/> class,
        /// which generates an NTLM authentication Authenticate (or Type 3) message.
        /// </summary>
        /// <param name="random">A <see cref="Random"/> object used to generate pseudorandom numbers for generating random keys.</param>
        /// <param name="currentTime"></param>
        /// <param name="domain">The domain against which to authenticate.</param>
        /// <param name="host">The host against which to authenticate.</param>
        /// <param name="user">The user name to use in authenticating.</param>
        /// <param name="password">The password to use in authenticating.</param>
        /// <param name="nonce">The random byte array sent by the server as part of the challenge message.</param>
        /// <param name="negotiatedOptionFlags">The <see cref="NtlmNegotiateFlags"/> sent by the server as part of the challenge message.</param>
        /// <param name="target">The target sent by the server as part of the challenge message.</param>
        /// <param name="targetInformation">The target information structure as an array of bytes sent by the server as part of the challenge message.</param>
        public NtlmAuthenticateMessageGenerator(Random random, DateTime currentTime, string domain, string host, string user, string password, byte[] nonce, NtlmNegotiateFlags negotiatedOptionFlags, string target, byte[] targetInformation)
            : this(random, currentTime, domain, host, user, password, nonce, negotiatedOptionFlags, target, targetInformation, null, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmAuthenticateMessageGenerator"/> class,
        /// which generates an NTLM authentication Authenticate (or Type 3) message.
        /// </summary>
        /// <param name="domain">The domain against which to authenticate.</param>
        /// <param name="host">The host against which to authenticate.</param>
        /// <param name="user">The user name to use in authenticating.</param>
        /// <param name="password">The password to use in authenticating.</param>
        /// <param name="nonce">The random byte array sent by the server as part of the challenge message.</param>
        /// <param name="negotiatedOptionFlags">The <see cref="NtlmNegotiateFlags"/> sent by the server as part of the challenge message.</param>
        /// <param name="target">The target sent by the server as part of the challenge message.</param>
        /// <param name="targetInformation">The target information structure as an array of bytes sent by the server as part of the challenge message.</param>
        /// <param name="peerServerCertificate">An <see cref="X509Certificate"/> used to cryptographically sign communication between the server and client.</param>
        /// <param name="type1Message">A byte array containing the Negotiate (or Type 1) message used in the handshake.</param>
        /// <param name="type2Message">A byte array containing the Challenge (or Type 2) message used in the handshake.</param>
        public NtlmAuthenticateMessageGenerator(string domain, string host, string user, string password, byte[] nonce, NtlmNegotiateFlags negotiatedOptionFlags, string target,  byte[] targetInformation, X509Certificate peerServerCertificate, byte[] type1Message, byte[] type2Message) 
            : this(RandomValueGenerator, DateTime.Now, domain, host, user, password, nonce, negotiatedOptionFlags, target, targetInformation, peerServerCertificate, type1Message, type2Message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmAuthenticateMessageGenerator"/> class,
        /// which generates an NTLM authentication Authenticate (or Type 3) message.
        /// </summary>
        /// <param name="random">A <see cref="Random"/> object used to generate pseudorandom numbers for generating random keys.</param>
        /// <param name="currentTime"></param>
        /// <param name="domain">The domain against which to authenticate.</param>
        /// <param name="host">The host against which to authenticate.</param>
        /// <param name="user">The user name to use in authenticating.</param>
        /// <param name="password">The password to use in authenticating.</param>
        /// <param name="nonce">The random byte array sent by the server as part of the challenge message.</param>
        /// <param name="negotiatedOptionFlags">The <see cref="NtlmNegotiateFlags"/> sent by the server as part of the challenge message.</param>
        /// <param name="target">The target sent by the server as part of the challenge message.</param>
        /// <param name="targetInformation">The target information structure as an array of bytes sent by the server as part of the challenge message.</param>
        /// <param name="peerServerCertificate">An <see cref="X509Certificate"/> used to cryptographically sign communication between the server and client.</param>
        /// <param name="type1Message">A byte array containing the Negotiate (or Type 1) message used in the handshake.</param>
        /// <param name="type2Message">A byte array containing the Challenge (or Type 2) message used in the handshake.</param>
        public NtlmAuthenticateMessageGenerator(Random random, DateTime currentTime, string domain, string host, string user, string password, byte[] nonce, NtlmNegotiateFlags negotiatedOptionFlags, string target, byte[] targetInformation, X509Certificate peerServerCertificate, byte[] type1Message, byte[] type2Message)
        {
            if (random == null)
            {
                throw new NtlmAuthorizationGenerationException("Random generator not available");
            }

            // Save the flags
            this.negotiatedOptionFlags = negotiatedOptionFlags;
            this.type1Message = type1Message;
            this.type2Message = type2Message;

            // Strip off domain name from the host!
            string unqualifiedHost = ConvertHost(host);
            
            // Use only the base domain name!
            string unqualifiedDomain = ConvertDomain(domain);

            byte[] responseTargetInformation = targetInformation;
            if (peerServerCertificate != null)
            {
                responseTargetInformation = AddGssMessageIntegrityCodeAttributeValuesToTargetInfo(targetInformation, peerServerCertificate);
                isMessageIntegrityCodeRequired = true;
            }
            else
            {
                isMessageIntegrityCodeRequired = false;
            }

            // Create a cipher generator class.
            // N.B., Use original domain value (before modification).
            CipherGen gen = new CipherGen(random, currentTime, unqualifiedDomain, user, password, nonce, target, responseTargetInformation);

            // Use the new code to calculate the responses, including v2 if that
            // seems warranted.
            byte[] userSessionKey;
            try
            {
                // This conditional may not work on Windows Server 2008 R2 and above,
                // where it has not yet been tested
                if (((negotiatedOptionFlags & NtlmNegotiateFlags.RequestTargetInfo) != 0) && targetInformation != null && target != null)
                {
                    // NTLMv2
                    ntlmResponse = gen.GetNtlmV2Response();
                    lmResponse = gen.GetLmV2Response();
                    if ((negotiatedOptionFlags & NtlmNegotiateFlags.RequestLanManagerKey) != 0)
                    {
                        userSessionKey = gen.GetLanManagerSessionKey();
                    }
                    else
                    {
                        userSessionKey = gen.GetNtlmV2UserSessionKey();
                    }
                }
                else
                {
                    // NTLMv1
                    if ((negotiatedOptionFlags & NtlmNegotiateFlags.RequestNtlmV2Session) != 0)
                    {
                        // NTLM2 session stuff is requested
                        ntlmResponse = gen.GetNtlm2SessionResponse();
                        lmResponse = gen.GetLm2SessionResponse();
                        if ((negotiatedOptionFlags & NtlmNegotiateFlags.RequestLanManagerKey) != 0)
                        {
                            userSessionKey = gen.GetLanManagerSessionKey();
                        }
                        else
                        {
                            userSessionKey = gen.GetNtlm2SessionResponseUserSessionKey();
                        }
                    }
                    else
                    {
                        ntlmResponse = gen.GetNtlmResponse();
                        lmResponse = gen.GetLmResponse();
                        if ((negotiatedOptionFlags & NtlmNegotiateFlags.RequestLanManagerKey) != 0)
                        {
                            userSessionKey = gen.GetLanManagerSessionKey();
                        }
                        else
                        {
                            userSessionKey = gen.GetNtlmUserSessionKey();
                        }
                    }
                }
            }
            catch (NtlmAuthorizationGenerationException)
            {
                // This likely means we couldn't find the MD4 hash algorithm -
                // fail back to just using LM
                ntlmResponse = new byte[0];
                lmResponse = gen.GetLmResponse();
                if ((negotiatedOptionFlags & NtlmNegotiateFlags.RequestLanManagerKey) != 0)
                {
                    userSessionKey = gen.GetLanManagerSessionKey();
                }
                else
                {
                    userSessionKey = gen.GetLmUserSessionKey();
                }
            }

            if ((negotiatedOptionFlags & NtlmNegotiateFlags.RequestSign) != 0)
            {
                if ((negotiatedOptionFlags & NtlmNegotiateFlags.RequestKeyExchange) != 0)
                {
                    exportedSessionKey = gen.GetSecondaryKey();
                    using (var rc4 = RC4.Create())
                    {
                        rc4.Key = exportedSessionKey;
                        sessionKey = rc4.CreateEncryptor().TransformFinalBlock(userSessionKey, 0, userSessionKey.Length);
                    }
                }
                else
                {
                    sessionKey = userSessionKey;
                    exportedSessionKey = sessionKey;
                }
            }
            else
            {
                if (isMessageIntegrityCodeRequired)
                {
                    throw new NtlmAuthorizationGenerationException("Cannot sign/seal: no exported session key");
                }

                sessionKey = null;
                exportedSessionKey = null;
            }

            Encoding charset = GetCharset(negotiatedOptionFlags);
            if (unqualifiedHost != null)
            {
                hostBytes = charset.GetBytes(unqualifiedHost);
            }

            if (unqualifiedDomain != null)
            {
                domainBytes = charset.GetBytes(unqualifiedDomain.ToUpperInvariant());
            }

            userBytes = charset.GetBytes(user);
        }

        /// <summary>
        /// Creates the NTLM authenticate (Type 3) message.
        /// </summary>
        protected override void BuildMessage()
        {
            int ntlmResponseLength = ntlmResponse.Length;
            int lmResponseLength = lmResponse.Length;

            int domainLength = domainBytes != null ? domainBytes.Length : 0;
            int hostLength = hostBytes != null ? hostBytes.Length : 0;
            int userLength = userBytes.Length;
            int sessionKeyLength;
            if (sessionKey != null)
            {
                sessionKeyLength = sessionKey.Length;
            }
            else
            {
                sessionKeyLength = 0;
            }

            // Calculate the layout within the packet
            int lmResponseOffset = 72;
            if (isMessageIntegrityCodeRequired)
            {
                lmResponseOffset += 16;
            }

            int ntlmResponseOffset = lmResponseOffset + lmResponseLength;
            int domainOffset = ntlmResponseOffset + ntlmResponseLength;
            int userOffset = domainOffset + domainLength;
            int hostOffset = userOffset + userLength;
            int sessionKeyOffset = hostOffset + hostLength;
            int finalLength = sessionKeyOffset + sessionKeyLength;

            // Start the response. Length includes signature and type
            InitializeMessage(finalLength, NtlmMessageType.Authenticate);

            // LM Resp Length (twice)
            AddUShort(lmResponseLength);
            AddUShort(lmResponseLength);

            // LM Resp Offset
            AddUInt(Convert.ToUInt32(lmResponseOffset));

            // NT Resp Length (twice)
            AddUShort(ntlmResponseLength);
            AddUShort(ntlmResponseLength);

            // NT Resp Offset
            AddUInt(Convert.ToUInt32(ntlmResponseOffset));

            // Domain length (twice)
            AddUShort(domainLength);
            AddUShort(domainLength);

            // Domain offset.
            AddUInt(Convert.ToUInt32(domainOffset));

            // User Length (twice)
            AddUShort(userLength);
            AddUShort(userLength);

            // User offset
            AddUInt(Convert.ToUInt32(userOffset));

            // Host length (twice)
            AddUShort(hostLength);
            AddUShort(hostLength);

            // Host offset
            AddUInt(Convert.ToUInt32(hostOffset));

            // Session key length (twice)
            AddUShort(sessionKeyLength);
            AddUShort(sessionKeyLength);

            // Session key offset
            AddUInt(Convert.ToUInt32(sessionKeyOffset));

            // Flags.
            AddUInt((uint)negotiatedOptionFlags);

            // OS version values (only used for debugging purposes,
            // so we are hard-coding 5.1.2600, or Windows XP). A
            // future version should likely query the actual OS.
            NtlmVersion version = new NtlmVersion(5, 1, 2600);
            AddBytes(version.AsBytes());

            int micPosition = -1;
            if (isMessageIntegrityCodeRequired)
            {
                micPosition = CurrentOutputPosition;
                CurrentOutputPosition += 16;
            }

            // Add the actual data
            AddBytes(lmResponse);
            AddBytes(ntlmResponse);
            AddBytes(domainBytes);
            AddBytes(userBytes);
            AddBytes(hostBytes);
            if (sessionKey != null)
            {
                AddBytes(sessionKey);
            }

            // Write the mic back into its slot in the message
            if (isMessageIntegrityCodeRequired)
            {
                // Computation of message integrity code (MIC) as specified
                // in [MS-NLMP] section 3.2.5.1.2.
                List<byte> data = new List<byte>();
                data.AddRange(type1Message);
                data.AddRange(type2Message);
                data.AddRange(MessageContents);
                byte[] mic;
                using (HMACMD5 hmac = new HMACMD5(exportedSessionKey))
                {
                    mic = hmac.ComputeHash(data.ToArray());
                }

                Array.Copy(mic, 0, MessageContents, micPosition, mic.Length);
            }
        }

        /**
         * Add GSS channel binding hash and MIC flag to the targetInfo.
         * Looks like this is needed if we want to use exported session key for GSS wrapping.
         */
        private byte[] AddGssMessageIntegrityCodeAttributeValuesToTargetInfo(byte[] originalTargetInfo, X509Certificate peerServerCertificate)
        {
            byte[] newTargetInfo = new byte[originalTargetInfo.Length + 8 + 20];
            int appendLength = originalTargetInfo.Length - 4; // last tag is MSV_AV_EOL, do not copy that
            Array.Copy(originalTargetInfo, 0, newTargetInfo, 0, appendLength);
            WriteUShort(newTargetInfo, (int)NtlmAttributeValueIds.Flags, appendLength);
            WriteUShort(newTargetInfo, 4, appendLength + 2);
            WriteUInt(newTargetInfo, (int)NtlmAttributeValueFlags.ClientProvidesMessageIntegrity, appendLength + 4);
            WriteUShort(newTargetInfo, (int)NtlmAttributeValueIds.ChannelBindings, appendLength + 8);
            WriteUShort(newTargetInfo, 16, appendLength + 10);

            byte[] channelBindingsHash;
            try
            {
                byte[] certBytes = peerServerCertificate.GetRawCertData();
                byte[] certHashBytes;
                using (var sha256 = SHA256.Create())
                {
                    certHashBytes = sha256.ComputeHash(certBytes);
                }

                byte[] channelBindingStruct = new byte[16 + 4 + MagicTlsServerEndPoint.Length + certHashBytes.Length];
                WriteUInt(channelBindingStruct, 0x00000035, 16);
                Array.Copy(MagicTlsServerEndPoint, 0, channelBindingStruct, 20, MagicTlsServerEndPoint.Length);
                Array.Copy(certHashBytes, 0, channelBindingStruct, 20 + MagicTlsServerEndPoint.Length, certHashBytes.Length);

                using (var md5 = MD5.Create())
                {
                    channelBindingsHash = md5.ComputeHash(channelBindingStruct);
                }
            }
            catch (Exception e)
            {
                throw new NtlmAuthorizationGenerationException(e.Message, e);
            }

            Array.Copy(channelBindingsHash, 0, newTargetInfo, appendLength + 12, 16);
            return newTargetInfo;
        }

        private static void WriteUShort(byte[] buffer, int value, int offset)
        {
            byte[] shortValue = BitConverter.GetBytes(Convert.ToUInt16(value));
            Array.Copy(shortValue, 0, buffer, offset, shortValue.Length);
        }

        private static void WriteUInt(byte[] buffer, int value, int offset)
        {
            byte[] longValue = BitConverter.GetBytes(value);
            Array.Copy(longValue, 0, buffer, offset, longValue.Length);
        }
    }
}
