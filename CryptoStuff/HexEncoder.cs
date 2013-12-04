using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bitnet.Client.Encoder
{
    public class HexEncoderSO
    {
        /// <summary>
        /// Fastest conversion according to http://stackoverflow.com/a/624379/328397
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string ByteArrayToHexViaByteManipulation(byte[] bytes, int startingByte, int maxbits)
        {
            char[] c = new char[bytes.Length * 2];
            byte b;
            for (int i = startingByte; i < bytes.Length && i < startingByte + maxbits; i++)
            {
                b = ((byte)(bytes[i] >> 4));
                c[i * 2] = (char)(b > 9 ? b + 0x37 : b + 0x30);
                b = ((byte)(bytes[i] & 0xF));
                c[i * 2 + 1] = (char)(b > 9 ? b + 0x37 : b + 0x30);
            }
            return new string(c);
        }

        public static string ByteArrayToHexViaByteManipulation(byte[] hash1)
        {
            return ByteArrayToHexViaByteManipulation(hash1, 0, hash1.Length);
        }

        public static byte[] ToByteArrayFromHex(string hexString)
        {
            if (hexString.Length % 2 != 0) throw new ArgumentException("String must have an even length");
            var array = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
            {
                array[i / 2] = ByteFromTwoChars(hexString[i], hexString[i + 1]);
            }
            return array;
        }
        static byte ByteFromTwoChars(char p, char p_2)
        {
            byte ret;
            if (p <= '9' && p >= '0')
            {
                ret = (byte)((p - '0') << 4);
            }
            else if (p <= 'f' && p >= 'a')
            {
                ret = (byte)((p - 'a' + 10) << 4);
            }
            else if (p <= 'F' && p >= 'A')
            {
                ret = (byte)((p - 'A' + 10) << 4);
            }
            else throw new ArgumentException("Char is not a hex digit: " + p, "p");

            if (p_2 <= '9' && p_2 >= '0')
            {
                ret |= (byte)((p_2 - '0'));
            }
            else if (p_2 <= 'f' && p_2 >= 'a')
            {
                ret |= (byte)((p_2 - 'a' + 10));
            }
            else if (p_2 <= 'F' && p_2 >= 'A')
            {
                ret |= (byte)((p_2 - 'A' + 10));
            }
            else throw new ArgumentException("Char is not a hex digit: " + p_2, "p_2");

            return ret;
        }

    }
}
