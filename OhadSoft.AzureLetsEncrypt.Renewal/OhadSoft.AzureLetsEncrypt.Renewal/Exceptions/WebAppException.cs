using System;
using System.Runtime.Serialization;

namespace OhadSoft.AzureLetsEncrypt.Renewal.Exceptions
{
    [Serializable]
    public class WebAppException : Exception
    {
        public string AffectedWebApp { get; set; }
        public string Issue { get; set; }

        public WebAppException(string webApp, string issue)
            : base(webApp + ": " + issue)
        {
            this.AffectedWebApp = webApp;
            this.Issue = issue;
        }

        public WebAppException()
        {
        }

        public WebAppException(string message)
            : base(message)
        {
        }

        public WebAppException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected WebAppException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
        }
    }
}
