namespace Authenticator.HttpModule.ServerCleanup
{
    #region using statements
    using System;
    using System.Runtime.Serialization;
    #endregion

    /// <summary>
    /// An exception which occurs on HttpModule protocol errors like
    /// invalid packets or malformed attributes.
    /// </summary>
    [Serializable]
    public class HttpModuleException : Exception
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public HttpModuleException()
        {
            // Add any type-specific logic, and supply the default message.
        }

        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public HttpModuleException(string message, Exception innerException)
            : base(message, innerException)
        {
            // Add any type-specific logic for inner exceptions.
        }

        /// <summary>
        /// Constructs a HttpModuleException with a message.
        /// </summary>
        /// <param name="message">message error message</param>
        public HttpModuleException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// type-specific serialization constructor logic
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected HttpModuleException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}