namespace System.Security.Cryptography
{
    /// <summary>
    /// Represents the base class from which all implementations of the RC4 algorithm must derive.
    /// </summary>
    public abstract class RC4 : SymmetricAlgorithm
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RC4"/> class.
        /// </summary>
        protected RC4()
        {
            KeySizeValue = 128;
            BlockSizeValue = 64;
            FeedbackSizeValue = BlockSizeValue;
            LegalBlockSizesValue = new KeySizes[] { new KeySizes(64, 64, 0) };
            LegalKeySizesValue = new KeySizes[] { new KeySizes(40, 2048, 8) };
        }

        /// <summary>
        /// Creates an instance of a cryptographic object to perform the RC4 algorithm.
        /// </summary>
        /// <returns>An instance of a cryptographic object.</returns>
        public static new RC4 Create()
        {
            return new RC4Managed();
        }

        /// <summary>
        /// Creates an instance of a cryptographic object to perform the specified 
        /// implementation of the RC4 algorithm.
        /// </summary>
        /// <param name="algName"></param>
        /// <returns>An instance of a cryptographic object.</returns>
        public static new RC4 Create(string algName)
        {
            object alg = CryptoConfig.CreateFromName(algName);
            if (alg == null)
            {
                alg = new RC4Managed();
            }

            return alg as RC4;
        }
    }
}
