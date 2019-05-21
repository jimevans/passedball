using System;

namespace PassedBall
{
    /// <summary>
    /// Exception thrown when encountering an error in calculating the ciphers used in NTLM authentication.
    /// </summary>
    public class NtlmAuthenticationCipherCalculationException : NtlmAuthorizationGenerationException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmAuthenticationCipherCalculationException"/> class.
        /// </summary>
        public NtlmAuthenticationCipherCalculationException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmAuthenticationCipherCalculationException"/> class.
        /// </summary>
        /// <param name="message">The message of the exception.</param>
        public NtlmAuthenticationCipherCalculationException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmAuthenticationCipherCalculationException"/> class.
        /// </summary>
        /// <param name="message">The message of the exception.</param>
        /// <param name="innerException">The inner <see cref="Exception"/> causing this exception.</param>
        public NtlmAuthenticationCipherCalculationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

    }
}
