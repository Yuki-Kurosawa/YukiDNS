using System.Collections.Specialized;
using System.Dynamic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;


namespace System.Web
{
    public class HttpRequest
    {
        private HttpListenerRequest _request;

        public HttpRequest(HttpListenerRequest request)
        {
            _request = request;
            NameValueCollection nvc = new NameValueCollection();
            string body = "";
            Stream bodyStream = InputStream;
            byte[] buffer = new byte[ContentLength];
            bodyStream.Read(buffer, 0, buffer.Length);
            body = ContentEncoding.GetString(buffer);
            _body = body;
            ParseForm();
        }

        public Encoding ContentEncoding => _request.ContentEncoding;

        public Stream InputStream => _request.InputStream;

        public string Path => _request.Url.AbsolutePath;

        public Uri Url => _request.Url;

        public string UserAgent => _request.UserAgent;

        public string UserHostAddress => _request.UserHostAddress;

        public string UserHostName => _request.UserHostName;
        public long ContentLength => _request.ContentLength64;

        public string ContentType => _request.ContentType;
        public NameValueCollection QueryString => _request.QueryString;

        public NameValueCollection Headers => _request.Headers;

        public CookieCollection Cookies => _request.Cookies;

        public NameValueCollection Form => _form;

        public string Body => _body;
        public string Method => _request.HttpMethod;

        public NameValueCollection _form;

        private string _body;

        private void ParseForm()
        {
            string body = Body;
            NameValueCollection nvc;
            if (TrySingleForm(body, out nvc) || TryMultiForm(body, out nvc))
            {
                _form = nvc;
                return;
            }
            _form= new NameValueCollection();
        }

        private bool TryMultiForm(string body,out NameValueCollection nvc)
        {
            nvc=new NameValueCollection();
            return false;
        }

        private bool TrySingleForm(string body,out NameValueCollection nvc)
        {
            nvc=new NameValueCollection();
            if (ContentType != "application/x-www-form-urlencoded")
            {
                return false;
            }
            string[] kvs = body.Split(new string[] {"&"}, StringSplitOptions.RemoveEmptyEntries);
            foreach (var kv in kvs)
            {
                string key = kv.Split('=')[0];
                string val = kv.Split('=').Length > 1 ? kv.Split('=')[1] : null;
                if (!string.IsNullOrEmpty(val))
                {
                    val=HttpUtility.UrlDecode(val);
                }
                nvc.Add(key,val);
            }
            return true;
        }
    }
}