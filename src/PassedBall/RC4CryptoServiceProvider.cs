namespace System.Security.Cryptography
{
    public class RC4CryptoServiceProvider : RC4, ICryptoTransform
    {
        private byte[] key;
        private byte[] state = new byte[256];
        private byte x;
        private byte y;
        private bool isDisposed;

        public RC4CryptoServiceProvider()
        {
        }

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

        public int InputBlockSize
        {
            get { return 1; }
        }

        public int OutputBlockSize
        {
            get { return 1; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public bool CanReuseTransform
        {
            get { return false; }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            CheckInput(inputBuffer, inputOffset, inputCount);
            CheckOutput(outputBuffer, outputOffset, inputCount);

            return InternalTransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            CheckInput(inputBuffer, inputOffset, inputCount);

            byte[] output = new byte[inputCount];
            InternalTransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            Key = rgbKey;
            return this;
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            Key = rgbKey;
            return this;
        }

        public override void GenerateIV()
        {
            // IV is not used for a stream cypher
            IVValue = new byte[0];
        }

        public override void GenerateKey()
        {
            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            int keySize = KeySizeValue >> 3;
            byte[] key = new byte[keySize];
            generator.GetBytes(key);
            KeyValue = key;
        }

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
