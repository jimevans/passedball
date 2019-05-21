namespace PassedBall
{
    /// <summary>
    /// Attribute-value identifiers (AvId) 
    /// according to [MS-NLMP] section 2.2.2.1
    /// </summary>
    public enum NtlmAttributeValueIds
    {
        /// <summary>
        /// Indicates that this is the last AV_PAIR in the list.
        /// </summary>
        EOL = 0x0000,

        /// <summary>
        /// The server's NetBIOS computer name.
        /// </summary>
        NetBiosComputerName = 0x0001,
        
        /// <summary>
        /// The server's NetBIOS domain name.
        /// </summary>
        NetBiosDomainName = 0x0002,

        /// <summary>
        /// The fully qualified domain name (FQDN) of the computer.
        /// </summary>
        DnsComputerName = 0x0003,

        /// <summary>
        /// The FQDN of the domain.
        /// </summary>
        DnsDomainName = 0x0004,

        /// <summary>
        /// The FQDN of the forest.
        /// </summary>
        DnsTreeName = 0x0005,

        /// <summary>
        /// A 32-bit value indicating server or client configuration.
        /// </summary>
        Flags = 0x0006,

        /// <summary>
        /// The server local time.
        /// </summary>
        Timestamp = 0x0007,

        /// <summary>
        /// A Single_Host_Data structure.
        /// </summary>
        SingleHost = 0x0008,

        /// <summary>
        /// The SPN of the target server.
        /// </summary>
        TargetName = 0x0009,

        /// <summary>
        /// A channel bindings hash.
        /// </summary>
        ChannelBindings = 0x000A
    }
}
