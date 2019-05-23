using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PassedBall
{
    /// <summary>
    /// Class that handles the generation of cryptographic cyphers for NTLM authentication.
    /// </summary>
    public class CipherGen
    {
        private readonly Random random;
        private readonly long currentTime;

        private readonly string domain;
        private readonly string user;
        private readonly string password;
        private readonly byte[] challenge;
        private readonly string target;
        private readonly byte[] targetInformation;

        // Information we can generate but may be passed in (for testing)
        private byte[] clientChallenge;
        private byte[] clientChallenge2;
        private byte[] secondaryKey;
        private byte[] timestamp;

        // Stuff we always generate
        private byte[] lmHash = null;
        private byte[] lmResponse = null;
        private byte[] ntlmHash = null;
        private byte[] ntlmResponse = null;
        private byte[] ntlmv2Hash = null;
        private byte[] lmv2Hash = null;
        private byte[] lmv2Response = null;
        private byte[] ntlmv2Blob = null;
        private byte[] ntlmv2Response = null;
        private byte[] ntlm2SessionResponse = null;
        private byte[] lm2SessionResponse = null;
        private byte[] lmUserSessionKey = null;
        private byte[] ntlmUserSessionKey = null;
        private byte[] ntlmv2UserSessionKey = null;
        private byte[] ntlm2SessionResponseUserSessionKey = null;
        private byte[] lanManagerSessionKey = null;

        /// <summary>
        /// Initializes a new instance of the <see cref="CipherGen"/> class.
        /// </summary>
        /// <param name="random">A <see cref="Random"/> object used for generating pseudorandom numbers.</param>
        /// <param name="currentTime">A <see cref="DateTime"/> structure representing the current time.</param>
        /// <param name="domain">The domain used to authenticate.</param>
        /// <param name="user">The user name used to authenticate.</param>
        /// <param name="password">The password used to authenticate.</param>
        /// <param name="challenge">A byte array representing the challenge from the server used for authentication.</param>
        /// <param name="target">The target provided by the challenge message.</param>
        /// <param name="targetInformation">The TargetInfo structures provided by the challenge message.</param>
        public CipherGen(Random random, DateTime currentTime, string domain, string user, string password, byte[] challenge, string target, byte[] targetInformation)
            : this(random, currentTime, domain, user, password, challenge, target, targetInformation, null, null, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CipherGen"/> class.
        /// </summary>
        /// <param name="random">A <see cref="Random"/> object used for generating pseudorandom numbers.</param>
        /// <param name="currentTime">A <see cref="DateTime"/> structure representing the current time.</param>
        /// <param name="domain">The domain used to authenticate.</param>
        /// <param name="user">The user name used to authenticate.</param>
        /// <param name="password">The password used to authenticate.</param>
        /// <param name="challenge">A byte array representing the challenge from the server used for authentication.</param>
        /// <param name="target">The target provided by the challenge message.</param>
        /// <param name="targetInformation">The TargetInfo structures provided by the challenge message.</param>
        /// <param name="clientChallenge">A byte array provided by the client as part of the negotiation.</param>
        /// <param name="clientChallenge2">A byte array provided by the client as part of the negotiation.</param>
        /// <param name="secondaryKey">A byte array provided by the client as part of the negotiation.</param>
        /// <param name="timestamp">A byte array representing a timestamp.</param>
        public CipherGen(Random random, DateTime currentTime, string domain, string user, string password, byte[] challenge, string target, byte[] targetInformation, byte[] clientChallenge, byte[] clientChallenge2, byte[] secondaryKey, byte[] timestamp)
        {
            this.random = random;
            this.currentTime = currentTime.Subtract(new DateTime(1601, 1, 1)).Ticks;

            this.domain = domain;
            this.target = target;
            this.user = user;
            this.password = password;
            this.challenge = challenge;
            this.targetInformation = targetInformation;
            this.clientChallenge = clientChallenge;
            this.clientChallenge2 = clientChallenge2;
            this.secondaryKey = secondaryKey;
            this.timestamp = timestamp;
        }

        /// <summary>
        /// Gets the Lan Manager (LM) response for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The Lan Manager response.</returns>
        public byte[] GetLmResponse()
        {
            if (lmResponse == null)
            {
                lmResponse = CalculateLmResponse(GetLmHash(), challenge);
            }

            return lmResponse;
        }

        /// <summary>
        /// Gets the NT Lan Manager (NTLM) response for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The NTLM response.</returns>
        public byte[] GetNtlmResponse()
        {
            if (ntlmResponse == null)
            {
                ntlmResponse = CalculateLmResponse(GetNtlmHash(), challenge);
            }

            return ntlmResponse;
        }

        /// <summary>
        /// Gets the Lan Manager version 2 (LMv2) response for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The LMv2 response.</returns>
        public byte[] GetLmV2Response()
        {
            if (lmv2Response == null)
            {
                lmv2Response = CalculateLmV2Response(GetLmV2Hash(), challenge, GetClientChallenge());
            }

            return lmv2Response;
        }

        /// <summary>
        /// Gets the NT Lan Manager version 2 (NTLMv2) response for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The NTLMv2 response.</returns>
        public byte[] GetNtlmV2Response()
        {
            if (ntlmv2Response == null)
            {
                ntlmv2Response = CalculateLmV2Response(GetNtlmV2Hash(), challenge, GetNtlmV2Blob());
            }

            return ntlmv2Response;
        }

        /// <summary>
        /// Gets the Lan Manager version 2 (LMv2) session response for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The LMv2 session response.</returns>
        public byte[] GetLm2SessionResponse()
        {
            if (lm2SessionResponse == null)
            {
                byte[] clntChallenge = GetClientChallenge();
                lm2SessionResponse = new byte[24];
                Array.Copy(clntChallenge, 0, lm2SessionResponse, 0, clntChallenge.Length);
                for (int i = clntChallenge.Length; i < lm2SessionResponse.Length; i++)
                {
                    lm2SessionResponse[i] = 0x00;
                }
            }

            return lm2SessionResponse;
        }

        /// <summary>
        /// Gets the NT Lan Manager 2 (NTLM2) session response for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The NTLM2 session response.</returns>
        public byte[] GetNtlm2SessionResponse()
        {
            if (ntlm2SessionResponse == null)
            {
                ntlm2SessionResponse = CalculateNtlm2SessionResponse(GetNtlmHash(), challenge, GetClientChallenge());
            }

            return ntlm2SessionResponse;
        }

        /// <summary>
        /// Gets the Lan Manager (LM) user session key for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The LM user session key.</returns>
        public byte[] GetLmUserSessionKey()
        {
            if (lmUserSessionKey == null)
            {
                lmUserSessionKey = new byte[16];
                Array.Copy(GetLmHash(), 0, lmUserSessionKey, 0, 8);
                for (int i = 8; i < 16; i++)
                {
                    lmUserSessionKey[i] = 0x00;
                }
            }

            return lmUserSessionKey;
        }

        /// <summary>
        /// Gets the NT Lan Manager (NTLM) user session key for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The NTLM user session key.</returns>
        public byte[] GetNtlmUserSessionKey()
        {
            if (ntlmUserSessionKey == null)
            {
                using (HashAlgorithm md4 = new MD4())
                {
                    ntlmUserSessionKey = md4.ComputeHash(GetNtlmHash());
                }
            }

            return ntlmUserSessionKey;
        }

        /// <summary>
        /// Gets the NT Lan Manager v2 (NTLMv2) user session key for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The NTLMv2 user session key.</returns>
        public byte[] GetNtlmV2UserSessionKey()
        {
            if (ntlmv2UserSessionKey == null)
            {
                byte[] ntlmv2hash = GetNtlmV2Hash();
                byte[] truncatedResponse = new byte[16];
                Array.Copy(GetNtlmV2Response(), 0, truncatedResponse, 0, 16);
                ntlmv2UserSessionKey = CalculateHmacMD5(truncatedResponse, ntlmv2hash);
            }

            return ntlmv2UserSessionKey;
        }

        /// <summary>
        /// Gets the NT Lan Manager 2 (NTLM2) session response user session key for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The NTLM2 session response user session key.</returns>
        public byte[] GetNtlm2SessionResponseUserSessionKey()
        {
            if (ntlm2SessionResponseUserSessionKey == null)
            {
                byte[] ntlm2SessionResponseNonce = GetLm2SessionResponse();
                byte[] sessionNonce = new byte[challenge.Length + ntlm2SessionResponseNonce.Length];
                Array.Copy(challenge, 0, sessionNonce, 0, challenge.Length);
                Array.Copy(ntlm2SessionResponseNonce, 0, sessionNonce, challenge.Length, ntlm2SessionResponseNonce.Length);
                ntlm2SessionResponseUserSessionKey = CalculateHmacMD5(sessionNonce, GetNtlmUserSessionKey());
            }

            return ntlm2SessionResponseUserSessionKey;
        }

        /// <summary>
        /// Gets the Lan Manager (LM) session key for the given initialization values of this <see cref="CipherGen"/> class.
        /// </summary>
        /// <returns>The LM session key.</returns>
        public byte[] GetLanManagerSessionKey()
        {
            if (lanManagerSessionKey == null)
            {
                try
                {
                    byte[] keyBytes = new byte[14];
                    Array.Copy(GetLmHash(), 0, keyBytes, 0, 8);
                    for (int i = 8; i < keyBytes.Length; i++)
                    {
                        keyBytes[i] = 0xbd;
                    }

                    byte[] lowKey = CreateDESKeyBytes(keyBytes, 0);
                    byte[] highKey = CreateDESKeyBytes(keyBytes, 7);
                    byte[] truncatedResponse = new byte[8];
                    Array.Copy(GetLmResponse(), 0, truncatedResponse, 0, truncatedResponse.Length);
                    byte[] lowPart;
                    byte[] highPart;
                    using (DES des = DES.Create())
                    {
                        des.Padding = PaddingMode.None;
                        des.Mode = CipherMode.ECB;
                        des.Key = lowKey;
                        lowPart = des.CreateEncryptor().TransformFinalBlock(truncatedResponse, 0, truncatedResponse.Length);
                        des.Key = highKey;
                        highPart = des.CreateEncryptor().TransformFinalBlock(truncatedResponse, 0, truncatedResponse.Length);
                    }

                    lanManagerSessionKey = new byte[16];
                    Array.Copy(lowPart, 0, lanManagerSessionKey, 0, lowPart.Length);
                    Array.Copy(highPart, 0, lanManagerSessionKey, lowPart.Length, highPart.Length);
                }
                catch (Exception e)
                {
                    throw new NtlmAuthenticationCipherCalculationException(e.Message, e);
                }
            }

            return lanManagerSessionKey;
        }

        /// <summary>
        /// Gets a 16 byte array filled with random values representing a secondary key.
        /// </summary>
        /// <returns></returns>
        public byte[] GetSecondaryKey()
        {
            if (secondaryKey == null)
            {
                secondaryKey = MakeSecondaryKey();
            }

            return secondaryKey;
        }

        /** Calculate and return client challenge */
        private byte[] GetClientChallenge()
        {
            if (clientChallenge == null)
            {
                clientChallenge = MakeRandomChallenge();
            }

            return clientChallenge;
        }

        /** Calculate and return second client challenge */
        private byte[] GetClientChallenge2()
        {
            if (clientChallenge2 == null)
            {
                clientChallenge2 = MakeRandomChallenge();
            }

            return clientChallenge2;
        }

        /** Calculate and return the LMHash */
        private byte[] GetLmHash()
        {
            if (lmHash == null)
            {
                lmHash = CalculateLmHash(password);
            }

            return lmHash;
        }

        /** Calculate and return the NTLMHash */
        private byte[] GetNtlmHash()
        {
            if (ntlmHash == null)
            {
                ntlmHash = CalculateNtlmHash(password);
            }

            return ntlmHash;
        }

        /** Calculate the LMv2 hash */
        private byte[] GetLmV2Hash()
        {
            if (lmv2Hash == null)
            {
                lmv2Hash = CalculateLmV2Hash(domain, user, GetNtlmHash());
            }

            return lmv2Hash;
        }

        /** Calculate the NTLMv2 hash */
        private byte[] GetNtlmV2Hash()
        {
            if (ntlmv2Hash == null)
            {
                ntlmv2Hash = CalculateNtlmV2Hash(domain, user, GetNtlmHash());
            }

            return ntlmv2Hash;
        }

        /** Calculate a timestamp */
        private byte[] GetTimestamp()
        {
            if (timestamp == null)
            {
                timestamp = BitConverter.GetBytes(this.currentTime);
            }

            return timestamp;
        }

        /** Calculate the NTLMv2Blob */
        private byte[] GetNtlmV2Blob()
        {
            if (ntlmv2Blob == null)
            {
                ntlmv2Blob = CreateBlob(GetClientChallenge2(), targetInformation, GetTimestamp());
            }

            return ntlmv2Blob;
        }

        /** Calculate a challenge block */
        private byte[] MakeRandomChallenge()
        {
            byte[] rval = new byte[8];
            random.NextBytes(rval);
            return rval;
        }

        /** Calculate a 16-byte secondary key */
        private byte[] MakeSecondaryKey()
        {
            byte[] rval = new byte[16];
            random.NextBytes(rval);
            return rval;
        }

        /** Calculates HMAC-MD5 */
        private byte[] CalculateHmacMD5(byte[] value, byte[] key)
        {
            byte[] output;
            using (HMACMD5 hmac = new HMACMD5(key))
            {
                output = hmac.ComputeHash(value);
            }

            return output;
        }

        /**
         * Calculates the NTLM2 Session Response for the given challenge, using the
         * specified password and client challenge.
         *
         * @return The NTLM2 Session Response. This is placed in the NTLM response
         *         field of the Type 3 message; the LM response field contains the
         *         client challenge, null-padded to 24 bytes.
         */
        private byte[] CalculateNtlm2SessionResponse(byte[] ntlmHash, byte[] challenge, byte[] clientChallenge)
        {
            try
            {
                byte[] digest;
                using (HashAlgorithm md5 = MD5.Create())
                {
                    byte[] content = new byte[challenge.Length + clientChallenge.Length];
                    Array.Copy(challenge, 0, content, 0, challenge.Length);
                    Array.Copy(clientChallenge, 0, content, challenge.Length, clientChallenge.Length);
                    digest = md5.ComputeHash(content);
                }

                byte[] sessionHash = new byte[8];
                Array.Copy(digest, 0, sessionHash, 0, 8);
                return CalculateLmResponse(ntlmHash, sessionHash);
            }
            catch (Exception e)
            {
                if (e is NtlmAuthenticationCipherCalculationException)
                {
                    throw e;
                }

                throw new NtlmAuthenticationCipherCalculationException(e.Message, e);
            }
        }

        /**
         * Creates the LM Hash of the user's password.
         *
         * @param password
         *            The password.
         *
         * @return The LM Hash of the given password, used in the calculation of the
         *         LM Response.
         */
        private byte[] CalculateLmHash(String password)
        {
            try
            {
                byte[] oemPassword = Encoding.ASCII.GetBytes(password.ToUpperInvariant());
                int length = Math.Min(oemPassword.Length, 14);
                byte[] keyBytes = new byte[14];
                Array.Copy(oemPassword, 0, keyBytes, 0, length);
                byte[] lowKey = CreateDESKeyBytes(keyBytes, 0);
                byte[] highKey = CreateDESKeyBytes(keyBytes, 7);
                byte[] magicConstant = Encoding.ASCII.GetBytes("KGS!@#$%");

                byte[] lowHash;
                byte[] highHash;
                using (DES des = DES.Create())
                {
                    des.Padding = PaddingMode.None;
                    des.Mode = CipherMode.ECB;
                    des.Key = lowKey;
                    lowHash = des.CreateEncryptor().TransformFinalBlock(magicConstant, 0, magicConstant.Length);
                    des.Key = highKey;
                    highHash = des.CreateEncryptor().TransformFinalBlock(magicConstant, 0, magicConstant.Length);
                }

                byte[] lmHash = new byte[16];
                Array.Copy(lowHash, 0, lmHash, 0, 8);
                Array.Copy(highHash, 0, lmHash, 8, 8);
                return lmHash;
            }
            catch (Exception e)
            {
                throw new NtlmAuthenticationCipherCalculationException(e.Message, e);
            }
        }

        /**
         * Creates the NTLM Hash of the user's password.
         *
         * @param password
         *            The password.
         *
         * @return The NTLM Hash of the given password, used in the calculation of
         *         the NTLM Response and the NTLMv2 and LMv2 Hashes.
         */
        private byte[] CalculateNtlmHash(String password)
        {
            byte[] unicodePassword = Encoding.Unicode.GetBytes(password);
            byte[] hash;
            using (HashAlgorithm md4 = new MD4())
            {
                hash = md4.ComputeHash(unicodePassword);
            }

            return hash;
        }

        /**
         * Creates the LMv2 Hash of the user's password.
         *
         * @return The LMv2 Hash, used in the calculation of the NTLMv2 and LMv2
         *         Responses.
         */
        private byte[] CalculateLmV2Hash(String domain, String user, byte[] ntlmHash)
        {
            List<byte> data = new List<byte>();
            data.AddRange(Encoding.Unicode.GetBytes(user.ToUpperInvariant()));
            if (domain != null)
            {
                data.AddRange(Encoding.Unicode.GetBytes(domain.ToUpperInvariant()));
            }

            return CalculateHmacMD5(data.ToArray(), ntlmHash);
        }

        /**
         * Creates the NTLMv2 Hash of the user's password.
         *
         * @return The NTLMv2 Hash, used in the calculation of the NTLMv2 and LMv2
         *         Responses.
         */
        private byte[] CalculateNtlmV2Hash(String domain, String user, byte[] ntlmHash)
        {
            List<byte> data = new List<byte>();
            data.AddRange(Encoding.Unicode.GetBytes(user.ToUpperInvariant()));
            if (domain != null)
            {
                data.AddRange(Encoding.Unicode.GetBytes(domain));
            }

            return CalculateHmacMD5(data.ToArray(), ntlmHash);
        }

        /**
         * Creates the LM Response from the given hash and Type 2 challenge.
         *
         * @param hash
         *            The LM or NTLM Hash.
         * @param challenge
         *            The server challenge from the Type 2 message.
         *
         * @return The response (either LM or NTLM, depending on the provided hash).
         */
        private byte[] CalculateLmResponse(byte[] hash, byte[] challenge)
        {
            try
            {
                byte[] keyBytes = new byte[21];
                Array.Copy(hash, 0, keyBytes, 0, 16);
                byte[] lowKey = CreateDESKeyBytes(keyBytes, 0);
                byte[] middleKey = CreateDESKeyBytes(keyBytes, 7);
                byte[] highKey = CreateDESKeyBytes(keyBytes, 14);

                byte[] lowResponse;
                byte[] middleResponse;
                byte[] highResponse;

                using (DES des = DES.Create())
                {
                    des.Padding = PaddingMode.None;
                    des.Mode = CipherMode.ECB;
                    des.Key = lowKey;
                    lowResponse = des.CreateEncryptor().TransformFinalBlock(challenge, 0, challenge.Length);
                    des.Key = middleKey;
                    middleResponse = des.CreateEncryptor().TransformFinalBlock(challenge, 0, challenge.Length);
                    des.Key = highKey;
                    highResponse = des.CreateEncryptor().TransformFinalBlock(challenge, 0, challenge.Length);
                }

                byte[] lmResponse = new byte[24];
                Array.Copy(lowResponse, 0, lmResponse, 0, 8);
                Array.Copy(middleResponse, 0, lmResponse, 8, 8);
                Array.Copy(highResponse, 0, lmResponse, 16, 8);
                return lmResponse;
            }
            catch (Exception e)
            {
                throw new NtlmAuthenticationCipherCalculationException(e.Message, e);
            }
        }

        /**
         * Creates the LMv2 Response from the given hash, client data, and Type 2
         * challenge.
         *
         * @param hash
         *            The NTLMv2 Hash.
         * @param clientData
         *            The client data (blob or client challenge).
         * @param challenge
         *            The server challenge from the Type 2 message.
         *
         * @return The response (either NTLMv2 or LMv2, depending on the client
         *         data).
         */
        private byte[] CalculateLmV2Response(byte[] hash, byte[] challenge, byte[] clientData)
        {
            List<byte> data = new List<byte>();
            data.AddRange(challenge);
            data.AddRange(clientData);
            byte[] mac = CalculateHmacMD5(data.ToArray(), hash);
            byte[] lmv2Response = new byte[mac.Length + clientData.Length];
            Array.Copy(mac, 0, lmv2Response, 0, mac.Length);
            Array.Copy(clientData, 0, lmv2Response, mac.Length, clientData.Length);
            return lmv2Response;
        }

        /**
         * Creates the NTLMv2 blob from the given target information block and
         * client challenge.
         *
         * @param targetInformation
         *            The target information block from the Type 2 message.
         * @param clientChallenge
         *            The random 8-byte client challenge.
         *
         * @return The blob, used in the calculation of the NTLMv2 Response.
         */
        private byte[] CreateBlob(byte[] clientChallenge, byte[] targetInformation, byte[] timestamp)
        {
            byte[] blobSignature = new byte[] { 0x01, 0x01, 0x00, 0x00 };
            byte[] reserved = new byte[] { 0x00, 0x00, 0x00, 0x00 };
            byte[] unknown1 = new byte[] { 0x00, 0x00, 0x00, 0x00 };
            byte[] unknown2 = new byte[] { 0x00, 0x00, 0x00, 0x00 };
            byte[] blob = new byte[blobSignature.Length + reserved.Length + timestamp.Length + 8
                    + unknown1.Length + targetInformation.Length + unknown2.Length];
            int offset = 0;
            Array.Copy(blobSignature, 0, blob, offset, blobSignature.Length);
            offset += blobSignature.Length;
            Array.Copy(reserved, 0, blob, offset, reserved.Length);
            offset += reserved.Length;
            Array.Copy(timestamp, 0, blob, offset, timestamp.Length);
            offset += timestamp.Length;
            Array.Copy(clientChallenge, 0, blob, offset, 8);
            offset += 8;
            Array.Copy(unknown1, 0, blob, offset, unknown1.Length);
            offset += unknown1.Length;
            Array.Copy(targetInformation, 0, blob, offset, targetInformation.Length);
            offset += targetInformation.Length;
            Array.Copy(unknown2, 0, blob, offset, unknown2.Length);
            offset += unknown2.Length;
            return blob;
        }

        private byte[] CreateDESKeyBytes(byte[] bytes, int offset)
        {
            byte[] keyBytes = new byte[7];
            Array.Copy(bytes, offset, keyBytes, 0, 7);
            byte[] material = new byte[8];
            material[0] = keyBytes[0];
            material[1] = (byte)(keyBytes[0] << 7 | (keyBytes[1] & 0xff) >> 1);
            material[2] = (byte)(keyBytes[1] << 6 | (keyBytes[2] & 0xff) >> 2);
            material[3] = (byte)(keyBytes[2] << 5 | (keyBytes[3] & 0xff) >> 3);
            material[4] = (byte)(keyBytes[3] << 4 | (keyBytes[4] & 0xff) >> 4);
            material[5] = (byte)(keyBytes[4] << 3 | (keyBytes[5] & 0xff) >> 5);
            material[6] = (byte)(keyBytes[5] << 2 | (keyBytes[6] & 0xff) >> 6);
            material[7] = (byte)(keyBytes[6] << 1);
            AdjustParityBits(material);
            return material;
        }

        /**
         * Applies odd parity to the given byte array.
         *
         * @param bytes
         *            The data whose parity bits are to be adjusted for odd parity.
         */
        private void AdjustParityBits(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                byte currentByte = bytes[i];
                bool needsParity = (((currentByte >> 7) ^ (currentByte >> 6) ^ (currentByte >> 5)
                        ^ (currentByte >> 4) ^ (currentByte >> 3)
                        ^ (currentByte >> 2) ^ (currentByte >> 1)) & 0x01) == 0;
                if (needsParity)
                {
                    bytes[i] |= 0x01;
                }
                else
                {
                    bytes[i] &= 0xfe;
                }
            }
        }
    }
}
