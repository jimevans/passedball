using System.Collections.Generic;
using System.Linq;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Computes the MD4 hash value for the input data.
    /// </summary>
    public class MD4 : HashAlgorithm
    {
        private uint registerA;
        private uint registerB;
        private uint registerC;
        private uint registerD;
        private readonly uint[] currentBlock;
        private int bytesProcessed;

        /// <summary>
        /// Initializes a new instance of the <see cref="MD4"/> class.
        /// </summary>
        public MD4()
        {
            currentBlock = new uint[16];
            Initialize();
        }

        /// <summary>
        /// Initializes, or re-initializes, the instance of the hash algorithm.
        /// </summary>
        public override void Initialize()
        {
            registerA = 0x67452301;
            registerB = 0xefcdab89;
            registerC = 0x98badcfe;
            registerD = 0x10325476;
            bytesProcessed = 0;
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="offset">The offset into the byte array from which to begin using data.</param>
        /// <param name="length">The number of bytes in the byte array to use as data.</param>
        protected override void HashCore(byte[] array, int offset, int length)
        {
            ProcessMessage(Bytes(array, offset, length));
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>The computed hash code.</returns>
        protected override byte[] HashFinal()
        {
            try
            {
                ProcessMessage(Padding());

                return new[] { registerA, registerB, registerC, registerD }.SelectMany(BitConverter.GetBytes).ToArray();
            }
            finally
            {
                Initialize();
            }
        }

        private void ProcessMessage(IEnumerable<byte> bytes)
        {
            foreach (byte currentByte in bytes)
            {
                int c = bytesProcessed & 63;
                int i = c >> 2;
                int s = (c & 3) << 3;

                currentBlock[i] = (currentBlock[i] & ~((uint)255 << s)) | ((uint)currentByte << s);

                if (c == 63)
                {
                    Process16WordBlock();
                }

                bytesProcessed++;
            }
        }

        private static IEnumerable<byte> Bytes(byte[] bytes, int offset, int length)
        {
            for (int i = offset; i < length; i++)
            {
                yield return bytes[i];
            }
        }

        private IEnumerable<byte> Bytes(uint word)
        {
            yield return (byte)(word & 255);
            yield return (byte)((word >> 8) & 255);
            yield return (byte)((word >> 16) & 255);
            yield return (byte)((word >> 24) & 255);
        }

        private IEnumerable<byte> Repeat(byte value, int count)
        {
            for (int i = 0; i < count; i++)
            {
                yield return value;
            }
        }

        private IEnumerable<byte> Padding()
        {
            return Repeat(128, 1)
               .Concat(Repeat(0, ((bytesProcessed + 8) & 0x7fffffc0) + 55 - bytesProcessed))
               .Concat(Bytes((uint)bytesProcessed << 3))
               .Concat(Repeat(0, 4));
        }

        private void Process16WordBlock()
        {
            uint aa = registerA;
            uint bb = registerB;
            uint cc = registerC;
            uint dd = registerD;

            foreach (int k in new[] { 0, 4, 8, 12 })
            {
                aa = Round1Operation(aa, bb, cc, dd, currentBlock[k], 3);
                dd = Round1Operation(dd, aa, bb, cc, currentBlock[k + 1], 7);
                cc = Round1Operation(cc, dd, aa, bb, currentBlock[k + 2], 11);
                bb = Round1Operation(bb, cc, dd, aa, currentBlock[k + 3], 19);
            }

            foreach (int k in new[] { 0, 1, 2, 3 })
            {
                aa = Round2Operation(aa, bb, cc, dd, currentBlock[k], 3);
                dd = Round2Operation(dd, aa, bb, cc, currentBlock[k + 4], 5);
                cc = Round2Operation(cc, dd, aa, bb, currentBlock[k + 8], 9);
                bb = Round2Operation(bb, cc, dd, aa, currentBlock[k + 12], 13);
            }

            foreach (int k in new[] { 0, 2, 1, 3 })
            {
                aa = Round3Operation(aa, bb, cc, dd, currentBlock[k], 3);
                dd = Round3Operation(dd, aa, bb, cc, currentBlock[k + 8], 9);
                cc = Round3Operation(cc, dd, aa, bb, currentBlock[k + 4], 11);
                bb = Round3Operation(bb, cc, dd, aa, currentBlock[k + 12], 15);
            }

            unchecked
            {
                registerA += aa;
                registerB += bb;
                registerC += cc;
                registerD += dd;
            }
        }

        private static uint ROL(uint value, int numberOfBits)
        {
            return (value << numberOfBits) | (value >> (32 - numberOfBits));
        }

        private static uint Round1Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROL(a + ((b & c) | (~b & d)) + xk, s);
            }
        }

        private static uint Round2Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROL(a + ((b & c) | (b & d) | (c & d)) + xk + 0x5a827999, s);
            }
        }

        private static uint Round3Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROL(a + (b ^ c ^ d) + xk + 0x6ed9eba1, s);
            }
        }
    }
}
