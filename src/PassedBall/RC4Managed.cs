namespace System.Security.Cryptography
{
    /// <summary>
    /// Computes the <see cref="RC4"/> hash for the input data using the managed library.
    /// </summary>
    public class RC4Managed : RC4, ICryptoTransform
    {
        private byte[] key;
        private byte[] state = new byte[256];
        private byte x;
        private byte y;
        private bool isDisposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RC4Managed"/> class 
        /// using the managed library.
        /// </summary>
        public RC4Managed()
        {
        }

        /// <summary>
        /// Gets or sets the secret key for the <see cref="RC4"/> algorithm.
        /// </summary>
        public override byte[] Key
        {
            get
            {
                if (KeyValue == null)
                {
                    GenerateKey();
                }

                return KeyValue.Clone() as byte[];
            }

            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("Key");
                }

                byte[] key = value.Clone() as byte[];
                base.Key = key;
                KeySetup(key);
            }
        }

        /// <summary>
        /// Gets or sets the initialization vector (<see cref="IV"/>) for the RC4 algorithm.
        /// </summary>
        public override byte[] IV
        {
            get
            {
                if (IVValue == null)
                {
                    GenerateIV();
                }

                return IVValue;
            }

            set
            {
            }
        }

        /// <summary>
        /// Gets the input block size for the hash algorithm
        /// </summary>
        public int InputBlockSize
        {
            get { return 1; }
        }

        /// <summary>
        /// Gets the output block size for the hash algorithm.
        /// </summary>
        public int OutputBlockSize
        {
            get { return 1; }
        }

        /// <summary>
        /// Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        /// <summary>
        /// Gets a value indicating whether the current transform can be reused.
        /// </summary>
        public bool CanReuseTransform
        {
            get { return false; }
        }

        /// <summary>
        /// Computes the hash value for the specified region of the input byte array
        /// and copies the specified region of the input byte array to the specified
        /// region of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input to compute the hash code for.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <param name="outputBuffer">A copy of the part of the input array used to compute the hash code.</param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
        /// <returns>The number of bytes written.</returns>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            CheckInput(inputBuffer, inputOffset, inputCount);
            CheckOutput(outputBuffer, outputOffset, inputCount);

            return InternalTransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        /// <summary>
        /// Computes the hash value for the specified region of the specified byte array.
        /// </summary>
        /// <param name="inputBuffer">The input to compute the hash code for.</param>
        /// <param name="inputOffset">The offset into the byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the byte array to use as data.</param>
        /// <returns>An array that is a copy of the part of the input that is hashed.</returns>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            CheckInput(inputBuffer, inputOffset, inputCount);

            byte[] output = new byte[inputCount];
            InternalTransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        /// <summary>
        /// Creates a symmetric encryptor object with the specified <see cref="Key"/>
        /// property and initialization vector (<see cref="IV"/>).
        /// </summary>
        /// <param name="rgbKey">The secret key to use for the RC4 algorithm.</param>
        /// <param name="rgbIV">The initialization vector to use for the RC4 algorithm.</param>
        /// <returns>A symmetric encryptor object for the RC4 algorithm.</returns>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            Key = rgbKey;
            return this;
        }


        /// <summary>
        /// Creates a symmetric decryptor object with the specified <see cref="Key"/>
        /// property and initialization vector (<see cref="IV"/>).
        /// </summary>
        /// <param name="rgbKey">The secret key to use for the RC4 algorithm.</param>
        /// <param name="rgbIV">The initialization vector to use for the RC4 algorithm.</param>
        /// <returns>A symmetric decryptor object for the RC4 algorithm.</returns>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            Key = rgbKey;
            return this;
        }

        /// <summary>
        /// Generates a random initialization vector (<see cref="IV"/>) to use for the RC4 algorithm.
        /// </summary>
        public override void GenerateIV()
        {
            // IV is not used for a stream cypher
            IVValue = new byte[0];
        }

        /// <summary>
        /// Generates a random <see cref="Key"/> to use for the RC4 algorithm.
        /// </summary>
        public override void GenerateKey()
        {
            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            int keySize = KeySizeValue >> 3;
            byte[] key = new byte[keySize];
            generator.GetBytes(key);
            KeyValue = key;
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="RC4"/> algorithm
        /// and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><see langword="true"/> to release both managed
        /// and unmanaged resources; <see langword="false"/> to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            if (!isDisposed)
            {
                x = 0;
                y = 0;
                if (key != null)
                {
                    Array.Clear(key, 0, key.Length);
                    key = null;
                }
                Array.Clear(state, 0, state.Length);
                state = null;
                GC.SuppressFinalize(this);
                isDisposed = true;
            }
        }

        private void KeySetup(byte[] key)
        {
            byte index1 = 0;
            byte index2 = 0;

            for (int counter = 0; counter < 256; counter++)
            {
                state[counter] = (byte)counter;
            }

            x = 0;
            y = 0;
            for (int counter = 0; counter < 256; counter++)
            {
                index2 = (byte)(key[index1] + state[counter] + index2);
                // swap byte
                SwapBytes(state, counter, index2);
                index1 = (byte)((index1 + 1) % key.Length);
            }
        }

        private int InternalTransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            byte xorIndex;
            for (int counter = 0; counter < inputCount; counter++)
            {
                x = (byte)(x + 1);
                y = (byte)(state[x] + y);
                // swap byte
                SwapBytes(state, x, y);

                xorIndex = (byte)(state[x] + state[y]);
                outputBuffer[outputOffset + counter] = (byte)(inputBuffer[inputOffset + counter] ^ state[xorIndex]);
            }
            return inputCount;
        }

        private void SwapBytes(byte[] buffer, int index1, int index2)
        {
            byte tmp = buffer[index1];
            buffer[index1] = buffer[index2];
            buffer[index2] = tmp;
        }

        private void CheckInput(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer == null)
            {
                throw new ArgumentNullException("inputBuffer");
            }

            if (inputOffset < 0)
            {
                throw new ArgumentOutOfRangeException("inputOffset", "< 0");
            }

            if (inputCount < 0)
            {
                throw new ArgumentOutOfRangeException("inputCount", "< 0");
            }

            // ordered to avoid possible integer overflow
            if (inputOffset > inputBuffer.Length - inputCount)
            {
                throw new ArgumentException("Offset is outside the size of the input", "inputBuffer");
            }
        }

        private static void CheckOutput(byte[] outputBuffer, int outputOffset, int inputCount)
        {
            // check output parameters
            if (outputBuffer == null)
            {
                throw new ArgumentNullException("outputBuffer");
            }

            if (outputOffset < 0)
            {
                throw new ArgumentOutOfRangeException("outputOffset", "< 0");
            }

            // ordered to avoid possible integer overflow
            if (outputOffset > outputBuffer.Length - inputCount)
            {
                throw new ArgumentException("Requested output offset is outside the size of the output buffer", "outputBuffer");
            }
        }
    }
}
