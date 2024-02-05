using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace YukiDNS.CA_CORE
{
    public static class RSACryptoHelper
    {
        public const string PrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
        public const string PrivateKeyFooter = "-----END RSA PRIVATE KEY-----";
        public const string PublicKeyHeader = "-----BEGIN PUBLIC KEY-----";
        public const string PublicKeyFooter = "-----BEGIN PUBLIC KEY-----";

        public static RSAParameters CreateNewKey(int length=2048)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(length);

            return rsa.ExportParameters(true);
        }        

        public static string RSAKeyToPem(RSAParameters rsaPara, bool isPrivateKey)
        {
            string empty = string.Empty;
            RsaKeyParameters rsaKeyParameters = !isPrivateKey ? new RsaKeyParameters(false, new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent)) : (RsaKeyParameters)new RsaPrivateCrtKeyParameters(new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent), new BigInteger(1, rsaPara.D), new BigInteger(1, rsaPara.P), new BigInteger(1, rsaPara.Q), new BigInteger(1, rsaPara.DP), new BigInteger(1, rsaPara.DQ), new BigInteger(1, rsaPara.InverseQ));
            using (TextWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject((object)rsaKeyParameters);
                pemWriter.Writer.Flush();
                empty = writer.ToString()!;
            }
            return empty;
        }

        public static RSAParameters PemToRSAKey(string pemKey)
        {
            string empty = string.Empty;
            object obj = null;
            using (StringReader reader = new StringReader(pemKey))
                obj = new PemReader((TextReader)reader).ReadObject();
            RSAParameters rsaKey;
            if (obj is AsymmetricCipherKeyPair)
            {
                RsaPrivateCrtKeyParameters crtKeyParameters = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)obj).Private;
                rsaKey = new RSAParameters()
                {
                    Modulus = crtKeyParameters.Modulus.ToByteArrayUnsigned(),
                    Exponent = crtKeyParameters.PublicExponent.ToByteArrayUnsigned(),
                    D = crtKeyParameters.Exponent.ToByteArrayUnsigned(),
                    P = crtKeyParameters.P.ToByteArrayUnsigned(),
                    Q = crtKeyParameters.Q.ToByteArrayUnsigned(),
                    DP = crtKeyParameters.DP.ToByteArrayUnsigned(),
                    DQ = crtKeyParameters.DQ.ToByteArrayUnsigned(),
                    InverseQ = crtKeyParameters.QInv.ToByteArrayUnsigned()
                };
            }
            else
            {
                RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)obj;
                rsaKey = new RSAParameters()
                {
                    Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                    Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
                };
            }
            return rsaKey;
        }

        public static byte[] Encrypt(RSAParameters para, byte[] data)
        {
            RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
            cryptoServiceProvider.ImportParameters(para);
            return cryptoServiceProvider.Encrypt(data, false);
        }

        public static byte[] Decrypt(RSAParameters para, byte[] data)
        {
            RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
            cryptoServiceProvider.ImportParameters(para);
            return cryptoServiceProvider.Decrypt(data, false);
        }

        public static byte[] Sign(RSAParameters para, byte[] data, string hashMethod)
        {
            RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
            cryptoServiceProvider.ImportParameters(para);
            return cryptoServiceProvider.SignData(data, HashAlgorithm.Create(hashMethod)!);
        }

        public static bool Verify(RSAParameters para, byte[] data, byte[] sign, string hashMethod)
        {
            RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
            cryptoServiceProvider.ImportParameters(para);
            return cryptoServiceProvider.VerifyData(data, HashAlgorithm.Create(hashMethod)!, sign);
        }

        public static byte[] StringToHex(string str) => Encoding.UTF8.GetBytes(str);

        public static byte[] Base64ToHex(string base64) => Convert.FromBase64String(base64);

        public static string HexToBase64(byte[] hex) => Convert.ToBase64String(hex);

        public static string HexToString(byte[] hex) => Encoding.UTF8.GetString(hex);

        public static string HexToByteString(byte[] hexs)
        {
            string str = "";
            foreach (byte num in hexs)
                str = str + num.ToString("X2") + " ";
            return str.Trim();
        }

        public static byte[] ByteStringToHex(string bytes)
        {
            List<byte> byteList = new List<byte>();
            bytes = bytes.ToUpper();
            bytes = bytes.Replace(" ", "");
            for (int index = 0; index < bytes.Length; index += 2)
            {
                char ch = bytes[index];
                string str1 = ch.ToString();
                ch = bytes[index + 1];
                string str2 = ch.ToString();
                byte num = byte.Parse(str1 + str2, NumberStyles.AllowHexSpecifier);
                byteList.Add(num);
            }
            return byteList.ToArray();
        }
    
    }
}
