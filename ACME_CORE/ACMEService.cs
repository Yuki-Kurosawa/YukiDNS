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
using System.Threading;

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
            var orderObj=NewOrder(httpClient, objDic, nonce, kid, new[] {
                "test.ksyuki.com",
                "test2.ksyuki.com"
            },acmeKey);
            
            //Get Authorization Info
            foreach(var i in orderObj.Authorizations)
            {
                var authObj = GetAuthorization(httpClient, i);

                nonce = GetNewNonce(httpClient, objDic);
                bool authResult = false?
                    ProceedDNS01Challenge(httpClient, nonce, acmeKey, kid, i, authObj)
                    :
                    ProceedHTTP01Challenge(httpClient, nonce, acmeKey, kid, i, authObj);

                if (!authResult)
                {
                    Console.WriteLine($"ACME challenge failed for \"{authObj.identifier.value}\", order cancelled.");
                    return;
                }

                break;
            }

        }

        private static bool ProceedHTTP01Challenge(HttpClient httpClient, string nonce, RSAParameters acmeKey, string kid, string authUrl, ACMEAuthObject authObj)
        {
            if (!Directory.Exists(".well-known/acme-challenge"))
            {
                Directory.CreateDirectory(".well-known/acme-challenge");
            }

            var httpAuthToken = authObj.challenges.Where(k => k.type == "http-01").ToList()[0].token;

            string httpAuthDigest = GetHTTP01AuthToken(httpAuthToken, acmeKey);

            Console.WriteLine($"Please place a file named \".well_known/acme-challenge/{httpAuthToken}\" with content:");
            Console.WriteLine(httpAuthDigest);

            File.WriteAllText($".well-known/acme-challenge/{httpAuthToken}", httpAuthDigest);

            Console.WriteLine("Please press enter key if record is ready");
            Console.ReadLine();

            TriggerAuthorization(httpClient, nonce, kid, acmeKey, authObj.challenges.Where(k => k.type == "http-01").ToList()[0]);

            int sec = 0;
            while (authObj.status == "pending")
            {
                Console.WriteLine(authObj.identifier.value + " token: " + authObj.challenges[0].token + " status: " + authObj.status);
                authObj = GetAuthorization(httpClient, authUrl);
                Thread.Sleep(10000);
                sec += 10;
                Console.WriteLine("Authorizing ... " + sec.ToString());
            }

            if (authObj.status == "valid")
            {
                Console.WriteLine($"ACME Authorized for \"{authObj.identifier.value}\"");

            }
            else
            {
                Console.WriteLine($"ACME Authorized for \"{authObj.identifier.value}\" failed" + ", message: " + authObj.challenges[0].error.detail);
            }

            return authObj.status == "valid";
        }


        private static string GetHTTP01AuthToken(string dnsAuthToken, RSAParameters acmeKey)
        {
            var jwk = new
            {
                e = Base64Tool.UrlEncode(acmeKey.Exponent),
                kty = "RSA",
                n = Base64Tool.UrlEncode(acmeKey.Modulus)
            };

            var jwkSHA2 = SHA256.HashData(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwk)));

            string jwkHash = dnsAuthToken + "." + Base64Tool.UrlEncode(jwkSHA2);

            return jwkHash;
        }



        private static bool ProceedDNS01Challenge(HttpClient httpClient, string nonce, RSAParameters acmeKey, string kid, string authUrl, ACMEAuthObject authObj)
        {
            var dnsAuthToken = authObj.challenges.Where(k => k.type == "dns-01").ToList()[0].token;

            string dnsAuthDigest = Base64Tool.UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(GetDNS01AuthToken(dnsAuthToken, acmeKey))));

            Console.WriteLine($"Please set a DNS TXT record named \"{authObj.identifier.value}\" with value: " + dnsAuthDigest);
            Console.WriteLine("Please press enter key if record is ready");
            Console.ReadLine();

            TriggerAuthorization(httpClient, nonce, kid, acmeKey, authObj.challenges.Where(k => k.type == "dns-01").ToList()[0]);

            int sec = 0;
            while (authObj.status == "pending")
            {
                Console.WriteLine(authObj.identifier.value + " token: " + authObj.challenges[0].token + " status: " + authObj.status);
                authObj = GetAuthorization(httpClient, authUrl);
                Thread.Sleep(10000);
                sec += 10;
                Console.WriteLine("Authorizing ... " + sec.ToString());
            }

            if (authObj.status == "valid")
            {
                Console.WriteLine($"ACME Authorized for \"{authObj.identifier.value}\"");

            }
            else
            {
                Console.WriteLine($"ACME Authorized for \"{authObj.identifier.value}\" failed" + ", message: " + authObj.challenges[0].error.detail);
            }

            return authObj.status == "valid";
        }

        private static string GetDNS01AuthToken(string dnsAuthToken, RSAParameters acmeKey)
        {
            var jwk = new
            {
                e = Base64Tool.UrlEncode(acmeKey.Exponent),
                kty = "RSA",
                n = Base64Tool.UrlEncode(acmeKey.Modulus)
            };

            var jwkSHA2 = SHA256.HashData(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(jwk)));

            string jwkHash = dnsAuthToken + "." + Base64Tool.UrlEncode(jwkSHA2);

            return jwkHash;
        }

        private static void TriggerAuthorization(HttpClient httpClient,string nonce, string kid, RSAParameters acmeKey, ACMEAuthChallenges challenge)
        {
            Dictionary<string, string> dicAuth = new Dictionary<string, string>();
            dicAuth["protected"] = Base64Tool.UrlEncodeFromString(JsonConvert.SerializeObject(new
            {
                alg = "RS256",
                nonce = nonce,
                url = challenge.url,
                kid = kid
            }));
            dicAuth["payload"] = Base64Tool.UrlEncodeFromString(JsonConvert.SerializeObject(new
            {
               
            }));

            var signAuth = RSACryptoHelper.Sign(acmeKey, Encoding.UTF8.GetBytes($@"{dicAuth["protected"]}.{dicAuth["payload"]}"), "SHA256");

            dicAuth["signature"] = Base64Tool.UrlEncode(signAuth);

            HttpContent authReq = new StringContent(JsonConvert.SerializeObject(dicAuth));

            authReq.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");

            var authResp = httpClient.PostAsync(challenge.url, authReq).Result;

            Console.WriteLine(authResp.Content.ReadAsStringAsync().Result);
        }

        public static ACMEAuthObject GetAuthorization(HttpClient httpClient, string authUrl)
        {
            var ret = httpClient.GetStringAsync(authUrl).Result;

            Console.WriteLine(ret);

            return JsonConvert.DeserializeObject<ACMEAuthObject>(ret);
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
    
        public static ACMEOrderObject NewOrder(HttpClient httpClient, JObject objDic,string nonce,string kid, string[] dnsNames, RSAParameters acmeKey)
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

            return new ACMEOrderObject()
            {
                OrderID = oid,
                FinalizeAction = jOrder.GetValue("finalize").ToString(),
                Authorizations = authorizations
            };
        }




    }
}
