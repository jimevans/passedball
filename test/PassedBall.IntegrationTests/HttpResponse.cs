using System;
using System.Collections.Generic;

namespace PassedBall.IntegrationTests
{
    /// <summary>
    /// Represents an HTTP response to a request from an HTTP server
    /// </summary>
    public class HttpResponse
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HttpResponse"/> class.
        /// </summary>
        /// <param name="rawResponse">The string containing the HTTP response.</param>
        public HttpResponse(string rawResponse)
        {
            string lineSeparator = "\r\n";
            string bodySeparator = "\r\n\r\n";

            int firstLineEnd = rawResponse.IndexOf(lineSeparator);
            int headerStart = firstLineEnd + lineSeparator.Length;
            int headerEnd = rawResponse.IndexOf(bodySeparator);
            int bodyStart = headerEnd + bodySeparator.Length;

            string firstLine = rawResponse.Substring(0, firstLineEnd);
            string rawHeaders = rawResponse.Substring(headerStart, headerEnd - headerStart);
            this.Body = rawResponse.Substring(bodyStart);

            string[] firstLineParts = firstLine.Split(' ');
            this.HttpVersion = firstLineParts[0];
            this.StatusCode = int.Parse(firstLineParts[1]);

            string[] headerValues = rawHeaders.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < headerValues.Length; i++)
            {
                if (Headers == null)
                {
                    Headers = new Dictionary<string, string>();
                }

                // If a header is supplied multiple times, add the new value to
                // the existing header value, separated by a carriage return /
                // line feed (CRLF) pair.
                string[] headerParts = headerValues[i].Split(new char[] { ':' }, 2);
                if (Headers.ContainsKey(headerParts[0]))
                {
                    Headers[headerParts[0]] += "\r\n" + headerParts[1].Trim();
                }
                else
                {
                    Headers[headerParts[0]] = headerParts[1].Trim();
                }
            }
        }

        /// <summary>
        /// Gets the HTTP version token from the response.
        /// </summary>
        public string HttpVersion { get; }

        /// <summary>
        /// Gets the status code of the response.
        /// </summary>
        public int StatusCode { get; }

        /// <summary>
        /// Gets the body of the response.
        /// </summary>
        public string Body { get; }

        /// <summary>
        /// Gets the set of headers sent as part of the response.
        /// </summary>
        public Dictionary<string, string> Headers { get; }
    }
}
