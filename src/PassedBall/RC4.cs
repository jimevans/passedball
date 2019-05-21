namespace System.Security.Cryptography
{
    public abstract class RC4 : SymmetricAlgorithm
    {
        public RC4()
        {
            KeySizeValue = 128;
            BlockSizeValue = 64;
            FeedbackSizeValue = BlockSizeValue;
            LegalBlockSizesValue = new KeySizes[] { new KeySizes(64, 64, 0) };
            LegalKeySizesValue = new KeySizes[] { new KeySizes(40, 2048, 8) };
        }

        public static new RC4 Create()
        {
            return new RC4CryptoServiceProvider();
        }

        public static new RC4 Create(string algName)
        {
            object alg = CryptoConfig.CreateFromName(algName);
            if (alg == null)
            {
                alg = new RC4CryptoServiceProvider();
            }

            return alg as RC4;
        }
    }
}
