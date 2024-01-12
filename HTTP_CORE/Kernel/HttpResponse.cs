using System.Collections.Specialized;
using System.Net;
using System.Text;

namespace System.Web
{
    public class HttpResponse
    {
        private HttpListenerResponse _response;

        public HttpResponse(HttpListenerResponse response)
        {
            _response = response;
        }

        public void Write(string str)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(str);
            ContentLength += bytes.Length;
            _response.OutputStream.Write(bytes, 0, bytes.Length);
            _response.OutputStream.Flush();
        }

        public void WriteBytes(byte[] bytes)
        {
            ContentLength += bytes.Length;
            _response.OutputStream.Write(bytes, 0, bytes.Length);
            _response.OutputStream.Flush();
        }

        public void End()
        {
            _response.OutputStream.Close();
        }

        public string ContentType
        {
            get { return _response.ContentType; }
            set { _response.ContentType = value; }
        }

        public Encoding ContentEncoding
        {
            get { return _response.ContentEncoding; }
            set { _response.ContentEncoding = value; }
        }

        public long ContentLength
        {
            get { return _response.ContentLength64; }
            set { _response.ContentLength64 = value; }
        }

        public WebHeaderCollection Headers
        {
            get { return _response.Headers; }
            set { _response.Headers = value; }
        }

        public CookieCollection Cookies
        {
            get { return _response.Cookies; }
            set { _response.Cookies = value; }
        }

        public int StatusCode
        {
            get { return _response.StatusCode; }
            set { _response.StatusCode = value; }
        }

        public string StatusDescription
        {
            get { return _response.StatusDescription; }
            set { _response.StatusDescription = value; }
        }
    }
}