using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Globalization;

namespace CryptTool
{
    public static class RSACryptoHelper
    {

        /// <summary>
        /// RSA密钥转Pem密钥
        /// </summary>
        /// <param name="RSAKey">RSA密钥</param>
        /// <param name="isPrivateKey">是否是私钥</param>
        /// <returns>Pem密钥</returns>
        public static string RSAKeyToPem(RSAParameters rsaPara, bool isPrivateKey)
        {
            string pemKey = string.Empty;
            RsaKeyParameters key = null;
            //RSA私钥
            if (isPrivateKey)
            {
                key = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent), new BigInteger(1, rsaPara.D),
                    new BigInteger(1, rsaPara.P), new BigInteger(1, rsaPara.Q), new BigInteger(1, rsaPara.DP), new BigInteger(1, rsaPara.DQ),
                    new BigInteger(1, rsaPara.InverseQ));
            }
            //RSA公钥
            else
            {
                key = new RsaKeyParameters(false,
                    new BigInteger(1, rsaPara.Modulus),
                    new BigInteger(1, rsaPara.Exponent));
            }
            using (TextWriter sw = new StringWriter())
            {
                var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
                pemWriter.WriteObject(key);
                pemWriter.Writer.Flush();
                pemKey = sw.ToString();
            }
            return pemKey;
        }

        /// <summary>
        /// Pem密钥转RSA密钥
        /// </summary>
        /// <param name="pemKey">Pem密钥</param>
        /// <param name="isPrivateKey">是否是私钥</param>
        /// <returns>RSA密钥</returns>
        public static RSAParameters PemToRSAKey(string pemKey)
        {
            string rsaKey = string.Empty;
            object pemObject = null;
            RSAParameters rsaPara = new RSAParameters();
            using (StringReader sReader = new StringReader(pemKey))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sReader);
                pemObject = pemReader.ReadObject();
            }

            //RSA私钥
            if (pemObject is AsymmetricCipherKeyPair)
            {
                RsaPrivateCrtKeyParameters key = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)pemObject).Private;

                rsaPara = new RSAParameters
                {
                    Modulus = key.Modulus.ToByteArrayUnsigned(),
                    Exponent = key.PublicExponent.ToByteArrayUnsigned(),
                    D = key.Exponent.ToByteArrayUnsigned(),
                    P = key.P.ToByteArrayUnsigned(),
                    Q = key.Q.ToByteArrayUnsigned(),
                    DP = key.DP.ToByteArrayUnsigned(),
                    DQ = key.DQ.ToByteArrayUnsigned(),
                    InverseQ = key.QInv.ToByteArrayUnsigned(),
                };
            }
            //RSA公钥
            else
            {
                RsaKeyParameters key = (RsaKeyParameters)pemObject;
                rsaPara = new RSAParameters
                {
                    Modulus = key.Modulus.ToByteArrayUnsigned(),
                    Exponent = key.Exponent.ToByteArrayUnsigned(),
                };
            }
            return rsaPara;
        }

        public static byte[] Encrypt(RSAParameters para,byte[] data)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(para);
            return rsa.Encrypt(data, false);
        }

        public static byte[] Decrypt(RSAParameters para,byte[] data)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(para);
            return rsa.Decrypt(data, false);
        }

        public static byte[] Sign(RSAParameters para,byte[] data,string hashMethod)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(para);
            return rsa.SignData(data, new HashAlgorithmName(hashMethod), RSASignaturePadding.Pkcs1);
        }

        public static bool Verify(RSAParameters para,byte[] data,byte[] sign, string hashMethod)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(para);
            return rsa.VerifyData(data, sign, new HashAlgorithmName(hashMethod), RSASignaturePadding.Pkcs1);
        }

        public static byte[] StringToHex(string str)
        {
            byte[] b=Encoding.UTF8.GetBytes(str);
            return b;
        }

        public static byte[] Base64ToHex(string base64)
        {
            return Convert.FromBase64String(base64);
        }

        public static string HexToBase64(byte[] hex)
        {
            return Convert.ToBase64String(hex);
        }

        public static string HexToString(byte[] hex)
        {
            string s = Encoding.UTF8.GetString(hex);
            return s;
        }

        public static string HexToByteString(byte[] hexs)
        {
            string str="";
            foreach(byte hex in hexs)
            {
                str += hex.ToString("X2")+" ";
            }
            return str.Trim();
        }

        public static byte[] ByteStringToHex(string bytes)
        {
            List<byte> hexs = new List<byte>();
            bytes = bytes.ToUpper();
            bytes = bytes.Replace(" ", "");
            for(var i = 0; i < bytes.Length; i += 2)
            {
                byte b = byte.Parse(bytes[i].ToString() + bytes[i + 1].ToString(), NumberStyles.AllowHexSpecifier);
                hexs.Add(b);
            }
            return hexs.ToArray();
        }
    }
}
