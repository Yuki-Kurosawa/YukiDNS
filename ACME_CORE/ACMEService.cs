using System;
using System.IO;
using System.Collections.Generic;
using System.Web;
using System.Net.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using YukiDNS.CA_CORE;
using System.Text;

namespace YukiDNS.ACME_CORE
{
    public class ACMEService
    {
        public static void Start()
        {
            HttpClient httpClient = new HttpClient();

            var retDic = httpClient.GetStringAsync("https://acme-staging-v02.api.letsencrypt.org/directory").Result;

            Console.WriteLine(retDic);

            var objDic=JsonConvert.DeserializeObject<JObject>(retDic);

            HttpRequestMessage newNonceReq = new HttpRequestMessage();
            newNonceReq.Method = HttpMethod.Head;
            newNonceReq.RequestUri = new Uri(objDic.GetValue("newNonce").ToString());

            var resp = httpClient.SendAsync(newNonceReq).Result;

            var hNonce = resp.Headers.GetValues("Replay-Nonce").ToList();

            Console.WriteLine($"{JsonConvert.SerializeObject(hNonce)}");

            string nonce = hNonce[0];

            RSAParameters acmeKey = RSACryptoHelper.CreateNewKey();
           

            Dictionary<string,string> dicNewAcct = new Dictionary<string,string>();
            dicNewAcct["protected"] = Base64Tool.UrlEncodeFromString(JsonConvert.SerializeObject(new 
            {
                alg="RS256",
                nonce=nonce,
                url= objDic.GetValue("newAccount").ToString(),
                jwk=new
                {
                    e=Base64Tool.UrlEncode(acmeKey.Exponent),
                    kty="RSA",
                    n=Base64Tool.UrlEncode(acmeKey.Modulus)
                }
            }));
            dicNewAcct["payload"] = Base64Tool.UrlEncodeFromString(JsonConvert.SerializeObject(new
            {
                termsOfServiceAgreed=true,
                contact = new[]
                {
                    "mailto:admin@test.com"
                }
            }));

            var sign = RSACryptoHelper.Sign(acmeKey, Encoding.UTF8.GetBytes($@"{dicNewAcct["protected"]}.{dicNewAcct["payload"]}"), "SHA256");

            dicNewAcct["signature"] = Base64Tool.UrlEncode(sign);


            HttpContent newAcctReq = new StringContent(JsonConvert.SerializeObject(dicNewAcct));

            newAcctReq.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");

            var newAcctResp = httpClient.PostAsync(objDic.GetValue("newAccount").ToString(), newAcctReq).Result;

            Console.WriteLine(newAcctResp.Content.ReadAsStringAsync().Result);
        }
    }
}
