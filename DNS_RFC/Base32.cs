using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YukiDNS.DNS_RFC
{
    public class Base32
    {
        /// <summary>
        /// Base 32 編碼
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string EncodeBase32(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;

            string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";
            var valueBytes = Encoding.UTF8.GetBytes(value);
            var encodedBuilder = new StringBuilder();
            var position = 0;
            var left = 0;
            for (var i = 0; i < valueBytes.Length * 8 / 5 + (valueBytes.Length * 8 % 5 == 0 ? 0 : 1); i++)
            {
                var encodedByte = default(byte);
                if (left > 0)
                {
                    encodedByte |= (byte)(valueBytes[position] << (8 - left));
                    if (left <= 5 && position < valueBytes.Length - 1)
                    {
                        position++;
                        if (left < 5) encodedByte |= (byte)(valueBytes[position] >> left);
                    }
                }
                else
                {
                    encodedByte |= valueBytes[position];
                }
                encodedBuilder.Append(Alphabet[(byte)(encodedByte >> 3)]);
                left = 8 * (position + 1) - 5 * (i + 1);
            }
            return encodedBuilder.ToString();
        }

        /// <summary>
        /// Base 32 解碼
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string DecodeBase32(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";
            value = value.ToLower().TrimEnd('=');

            var decodedBytes = new byte[value.Length * 5 / 8];
            var position = 0;
            var available = 0;

            for (var i = 0; i < value.Length; i++)
            {
                var symbol = (byte)(Alphabet.IndexOf(value[i]) << 3);
                if (available > 0)
                {
                    decodedBytes[position] |= (byte)(symbol >> (8 - available));
                    if (available <= 5 && position < decodedBytes.Length - 1)
                    {
                        decodedBytes[++position] |= (byte)(symbol << available);
                    }
                }
                else
                {
                    decodedBytes[position] |= symbol;
                }
                available = 8 * (position + 1) - 5 * (i + 1);
            }
            return Encoding.UTF8.GetString(decodedBytes);
        }
    }
}
