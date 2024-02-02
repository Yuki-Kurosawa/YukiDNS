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

            var objDic = JsonConvert.DeserializeObject<JObject>(retDic);

            string nonce = GetNewNonce(httpClient, objDic);


            RSAParameters acmeKey = RSACryptoHelper.CreateNewKey();

            Console.WriteLine("Creating New Account ......");

            //New Account            
            string kid = NewAccount(httpClient, objDic, nonce, new[] {
                "mailto:admin@test.com"
            },acmeKey  );

            nonce = GetNewNonce(httpClient, objDic);

            Console.WriteLine("Creating New Order ......");
            //New Order
            NewOrder(httpClient, objDic, nonce, kid, new[] {
                "test.ksyuki.com",
                "test2.ksyuki.com"
            },acmeKey);

        }

        public static string GetNewNonce(HttpClient httpClient, JObject objDic)
        {

            HttpRequestMessage newNonceReq = new HttpRequestMessage();
            newNonceReq.Method = HttpMethod.Head;
            newNonceReq.RequestUri = new Uri(objDic.GetValue("newNonce").ToString());

            var resp = httpClient.SendAsync(newNonceReq).Result;

            var hNonce = resp.Headers.GetValues("Replay-Nonce").ToList();

            Console.WriteLine($"{JsonConvert.SerializeObject(hNonce)}");

            string nonce = hNonce[0];

            return nonce;
        }

        public static string NewAccount(HttpClient httpClient, JObject objDic,string nonce, string[] contact, RSAParameters acmeKey)
        {
            Dictionary<string, string> dicNewAcct = new Dictionary<string, string>();
            dicNewAcct["protected"] = Base64Tool.UrlEncodeFromString(JsonConvert.SerializeObject(new
            {
                alg = "RS256",
                nonce = nonce,
                url = objDic.GetValue("newAccount").ToString(),
                jwk = new
                {
                    e = Base64Tool.UrlEncode(acmeKey.Exponent),
                    kty = "RSA",
                    n = Base64Tool.UrlEncode(acmeKey.Modulus)
                }
            }));
            dicNewAcct["payload"] = Base64Tool.UrlEncodeFromString(JsonConvert.SerializeObject(new
            {
                termsOfServiceAgreed = true,
                contact = contact
            }));

            var signAccount = RSACryptoHelper.Sign(acmeKey, Encoding.UTF8.GetBytes($@"{dicNewAcct["protected"]}.{dicNewAcct["payload"]}"), "SHA256");

            dicNewAcct["signature"] = Base64Tool.UrlEncode(signAccount);

            HttpContent newAcctReq = new StringContent(JsonConvert.SerializeObject(dicNewAcct));

            newAcctReq.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");

            var newAcctResp = httpClient.PostAsync(objDic.GetValue("newAccount").ToString(), newAcctReq).Result;

            Console.WriteLine(newAcctResp.Content.ReadAsStringAsync().Result);

            string kid = newAcctResp.Headers.GetValues("Location").ToList()[0];

            Console.WriteLine(kid);

            return kid;
        }
    
        public static string NewOrder(HttpClient httpClient, JObject objDic,string nonce,string kid, string[] dnsNames, RSAParameters acmeKey)
        {
            Dictionary<string, string> dicNewOrder = new Dictionary<string, string>();
            dicNewOrder["protected"] = Base64Tool.UrlEncodeFromString(JsonConvert.SerializeObject(new
            {
                alg = "RS256",
                nonce = nonce,
                url = objDic.GetValue("newOrder").ToString(),
                kid = kid
            }));

            List<dynamic> identifiers = new List<dynamic>();
            foreach(var dnsName in dnsNames)
            {
                identifiers.Add(new
                {
                    type = "dns",
                    value = dnsName,
                });
            }

            dicNewOrder["payload"] = Base64Tool.UrlEncodeFromString(JsonConvert.SerializeObject(new
            {
                identifiers = identifiers.ToArray()
            }));

            var signOrder = RSACryptoHelper.Sign(acmeKey, Encoding.UTF8.GetBytes($@"{dicNewOrder["protected"]}.{dicNewOrder["payload"]}"), "SHA256");

            dicNewOrder["signature"] = Base64Tool.UrlEncode(signOrder);
            HttpContent newOrderReq = new StringContent(JsonConvert.SerializeObject(dicNewOrder));

            newOrderReq.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");

            var newOrderResp = httpClient.PostAsync(objDic.GetValue("newOrder").ToString(), newOrderReq).Result;

            string retNewOrder = newOrderResp.Content.ReadAsStringAsync().Result;

            Console.WriteLine(retNewOrder);

            JObject jOrder = JsonConvert.DeserializeObject<JObject>(retNewOrder);

            string[] authorizations = JsonConvert.DeserializeObject<string[]>(JsonConvert.SerializeObject(jOrder.GetValue("authorizations")));
            string oid = newOrderResp.Headers.GetValues("Location").ToList()[0];

            Console.WriteLine(jOrder.GetValue("finalize").ToString());
            Console.WriteLine(JsonConvert.SerializeObject(authorizations));

            return oid;
        }

    }
}
