using System;

namespace PassedBall
{
    /// <summary>
    /// Class representing the NTLM version structure used in the protocol.
    /// </summary>
    public class NtlmVersion
    {
        private readonly byte[] versionInfo = new byte[8];

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmVersion"/> class.
        /// </summary>
        /// <param name="majorVersion">The major version of the OS.</param>
        /// <param name="minorVersion">The minor version of the OS.</param>
        /// <param name="productBuild">The product build of the OS.</param>
        public NtlmVersion(byte majorVersion, byte minorVersion, short productBuild)
        {
            versionInfo[0] = majorVersion;
            versionInfo[1] = minorVersion;

            byte[] buildBytes = BitConverter.GetBytes(productBuild);
            Array.Copy(buildBytes, 0, versionInfo, 2, buildBytes.Length);

            // Three bytes are reserved, and the protocol revision is 
            // hard-coded by the specification as 0x0f.
            byte[] protocolRevisionBytes = new byte[4] { 0x00, 0x00, 0x00, 0x0f };
            Array.Copy(protocolRevisionBytes, 0, versionInfo, 4, protocolRevisionBytes.Length);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NtlmVersion"/> class.
        /// </summary>
        /// <param name="bytes">A byte array representing the version.</param>
        public NtlmVersion(byte[] bytes)
        {
            Array.Copy(bytes, versionInfo, versionInfo.Length);
        }
        
        /// <summary>
        /// Gets the major version.
        /// </summary>
        public byte MajorVersion
        {
            get { return versionInfo[0]; }
        }

        /// <summary>
        /// Gets the minor version.
        /// </summary>
        public byte MinorVersion
        {
            get { return versionInfo[1]; }
        }

        /// <summary>
        /// Gets the build number.
        /// </summary>
        public short ProductBuild
        {
            get { return BitConverter.ToInt16(versionInfo, 2); }
        }

        /// <summary>
        /// Gets the revision number of the NTLM protocol.
        /// </summary>
        public byte NtlmProtocolRevision
        {
            get { return versionInfo[7]; }
        }


        /// <summary>
        /// Gets this <see cref="NtlmVersion"/> as an array of bytes.
        /// </summary>
        /// <returns>The version as an array of bytes.</returns>
        public byte[] AsBytes()
        {
            return versionInfo;
        }
    }
}
