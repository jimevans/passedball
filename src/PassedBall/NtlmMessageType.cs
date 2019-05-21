namespace PassedBall
{
    /// <summary>
    /// The supported message types for NTLM Authentication
    /// </summary>
    public enum NtlmMessageType : uint
    {
        /// <summary>
        /// Message is a Negotiate or "type 1" messsage.
        /// </summary>
        Negotiate = 1,

        /// <summary>
        /// Message is a Challenge response or "type 2" message.
        /// </summary>
        Challenge = 2,

        /// <summary>
        /// Message is an Authenticate or "type 3" message.
        /// </summary>
        Authenticate = 3
    }
}
