using Bitnet.Client.Encoder;
using Bitnet.Client.StackOverflow;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Bitnet.Client
{
    public enum HashMethod
    {
        nativeNet,
        Bouncy,
        nativeNetFips
    }
    
    public class Base58Check
    {
        public static string EncodePKToBase58Check(byte[] pkBytes, HashMethod method)
        {
            const int networkByte = 1;
            const int ripeHashLength = 20;
            const int twosComplimentByte = 1;
            const int sizeOfChecksum = 4;

            byte[] ripeHashNetwork = new byte[networkByte + ripeHashLength + sizeOfChecksum + twosComplimentByte];
            var arraySegment1 = new ArraySegmentWrapper(ripeHashNetwork, 0, networkByte + ripeHashLength);

            Org.BouncyCastle.Crypto.Digests.RipeMD160Digest ripe160Bouncy = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();

            System.Security.Cryptography.SHA256 sha256 = null;
            System.Security.Cryptography.RIPEMD160 ripe160 = null;

            string b582 = "";

            switch (method)
            {
                case HashMethod.nativeNet:
                    sha256 = new SHA256Managed();
                    ripe160 = new System.Security.Cryptography.RIPEMD160Managed();
                    break;
                case HashMethod.Bouncy:
                    break;
                case HashMethod.nativeNetFips:
                    sha256 = new SHA256CryptoServiceProvider();
                    ripe160 = new System.Security.Cryptography.RIPEMD160Managed();
                    break;
                default:
                    break;
            }

            // 2 - SHA-256 hash of 1  (32 bytes)
            byte[] hash1 = sha256.ComputeHash(pkBytes);

            // 3 - RIPEMD-160 Hash of 2  (20 bytes)      
            byte[] ripeHash = ripe160.ComputeHash(hash1);
            // ripe160Bouncy.BlockUpdate

            // 4 - Adding network bytes to 3 
            ripeHashNetwork[0] = 0x0;  // set the first bit accordingly
            Buffer.BlockCopy(ripeHash, 0, ripeHashNetwork, networkByte, ripeHashLength); // Array.Copy(ripeHash,0, ripeHashNetwork,1, ripeHashLength);

            // 5 - SHA-256 hash of 4 
            byte[] hash5 = sha256.ComputeHash(arraySegment1.ToStream(0, networkByte + ripeHashLength)); // 

            // 6 - SHA-256 hash of 5  
            byte[] hash6 = sha256.ComputeHash(hash5);

            // 7 - First four bytes of 6 
            Buffer.BlockCopy(hash6, 0, ripeHashNetwork, networkByte + ripeHashLength, 4);

            Array.Reverse(ripeHashNetwork, 0, networkByte + ripeHashLength + 4);
            BigInteger bi2 = new BigInteger(ripeHashNetwork);

            b582 = EncodeBase58(bi2);

            return b582;


            // Console.WriteLine(ArraySegmentWrapper.ByteArrayToHexViaByteManipulation(ripeHash) + Environment.NewLine + "010966776006953D5567439E5E39F86A0D273BEE");
            // Console.WriteLine(arraySegment1.ToHex(0, networkByte + ripeHashLength) + Environment.NewLine + "00010966776006953D5567439E5E39F86A0D273BEE");
            // Console.WriteLine(ArraySegmentWrapper.ByteArrayToHexViaByteManipulation(hash5) + Environment.NewLine + "445C7A8007A93D8733188288BB320A8FE2DEBD2AE1B47F0F50BC10BAE845C094");
            // Console.WriteLine(ArraySegmentWrapper.ByteArrayToHexViaByteManipulation(hash6) + Environment.NewLine + "D61967F63C7DD183914A4AE452C9F6AD5D462CE3D277798075B107615C1A8A30");

            //// Console.WriteLine(ArraySegmentWrapper.ByteArrayToHexViaByteManipulation(hash7) + Environment.NewLine + "D61967F6");
            // Console.WriteLine(ArraySegmentWrapper.ByteArrayToHexViaByteManipulation(ripeHashNetwork) + Environment.NewLine
            //     + "00010966776006953D5567439E5E39F86A0D273BEED61967F6");

            // // Base58 encoding of ripeHashNetworkChecksum
            // Console.WriteLine(ArraySegmentWrapper.ByteArrayToHexViaByteManipulation(ripeHashNetwork));
            // foreach (var item in ripeHashNetwork)
            // {
            //     Console.Write(item + ",");
            // }
            // Console.WriteLine();
            Console.WriteLine(b582);//



            // Byte to Hex string
            // ttp://stackoverflow.com/questions/623104/byte-to-hex-string


            //       var result = pubKey.GetBytes();
        }

        public class Check1DebugResult
        {

            public string T1PrivKeyHex { get; set; }

            public string T1PubKeyHex { get; set; }

            public string T1PubKeyBin { get; set; }

            public string T2SHAKeyHex { get; set; }

            public string T2SHAKeyBin { get; set; }

            public string T3SHAKeyHex { get; set; }

            public string T3SHAKeyBin { get; set; }

            public string T4RIPEKeyHex { get; set; }

            public string T4RIPEKeyBin { get; set; }

            public string T5SHAKeyHex { get; set; }

            public string T5SHAKeyBin { get; set; }

            public string T6SHAKeyHex { get; set; }

            public string T6SHAKeyBin { get; set; }

            public string T7CHKKeyHex { get; set; }

            public string T7CHKKeyBin { get; set; }

            public string T8ALLKeyHex { get; set; }

            public string T8ALLKeyBin { get; set; }

            public string T9twoKeyHex { get; set; }

            public string T9twoKeyBin { get; set; }

            public string T999Base58CheckOut { get; set; }
        }


        public static bool CheckBase58CheckTypo(string str)
        {
            System.Security.Cryptography.SHA256 sha256 = new SHA256Managed();


            const int networkByte = 1;
            const int ripeHashLength = 20;
            const int twosComplimentByte = 1;
            const int sizeOfChecksum = 4;

            var decodedBI = Base58Check.DecodeBase58(str);
            byte[] ripeHashNetwork = decodedBI.BigInt.ToByteArray();

            // Undo the endian mangling that AsBlockHashTarget just did...
            // Notice that .NET didn't protect us from two's compliment and we can't revert back to a AsBlockHashTarget without taking care of it.
            if (decodedBI.LeadingZeros > 0)
            {
                // todo: test... what happens if the last bit of the checksum 
                //byte[] ripeHash = new byte[ripeHashNetwork.Length + decodedBI.LeadingZeros];
                //Array.Copy(ripeHashNetwork, 0, ripeHash, decodedBI.LeadingZeros, ripeHashNetwork.Length);
                Array.Resize(ref ripeHashNetwork, ripeHashNetwork.Length + decodedBI.LeadingZeros);
            }
            Array.Reverse(ripeHashNetwork);


            //// 7 - Last four bytes   
            byte[] hash7 = new byte[4];
            Array.Copy(ripeHashNetwork, ripeHashNetwork.Length - 4, hash7, 0, 4);
            //Console.WriteLine(HexEncoder.ByteArrayToHexViaByteManipulation(hash7) + Environment.NewLine + "D61967F6");


            // 
            // Now do a checksum on the key and see if it's a typo
            //

            byte[] typoChecker = new byte[networkByte + ripeHashLength];
            Array.Copy(ripeHashNetwork, 0, typoChecker, 0, networkByte + ripeHashLength);

            // 5 - SHA-256 hash of 4 //
            byte[] hash5 = sha256.ComputeHash(typoChecker); // 
            //Console.WriteLine(HexEncoder.ByteArrayToHexViaByteManipulation(hash5) + Environment.NewLine + "445C7A8007A93D8733188288BB320A8FE2DEBD2AE1B47F0F50BC10BAE845C094");
            //ret1.T5SHAKeyHex = HexEncoder.ByteArrayToHexViaByteManipulation(hash5);
            //ret1.T5SHAKeyBin = GetBytesAsString(hash5);

            //6 - SHA-256 hash of 5  // 
            byte[] hash6 = sha256.ComputeHash(hash5); //  
            // Console.WriteLine(HexEncoder.ByteArrayToHexViaByteManipulation(hash6) + Environment.NewLine + "D61967F63C7DD183914A4AE452C9F6AD5D462CE3D277798075B107615C1A8A30");
            // ret1.T6SHAKeyHex = HexEncoder.ByteArrayToHexViaByteManipulation(hash6);
            // ret1.T6SHAKeyBin = GetBytesAsString(hash6);

            //
            // Do the last 4 bytes match
            //
            byte[] hash7test = new byte[4];
            Array.Copy(hash6, 0, hash7test, 0, 4);
            if (ArraySegmentWrapper.ArraysEqual<byte>(hash7test, hash7))
            {
                // Validation PASSED
            }
            else
            {
                // Validation FAILED
                return false;
            }

            //
            // Is the network type correct (keys are network specific!)
            //

            return false;
        }

        public static Check1DebugResult EncodePKToBase58Check1(byte[] pubKey, bool doVerify)
        {
            Check1DebugResult ret1 = new Check1DebugResult();

            System.Security.Cryptography.SHA256 sha256 = new SHA256Managed();
            //  System.Security.Cryptography.SHA256 sha256 = new SHA256CryptoServiceProvider(); // FIPS compliant
            System.Security.Cryptography.RIPEMD160 ripe160 = new System.Security.Cryptography.RIPEMD160Managed();

            const int networkByte = 1;
            const int ripeHashLength = 20;
            //const int twosComplimentByte = 1;
            const int sizeOfChecksum = 4;

            byte[] ripeHashNetwork = new byte[networkByte + ripeHashLength + sizeOfChecksum// + twosComplimentByte
                ];
            var arraySegment1 = new ArraySegmentWrapper(ripeHashNetwork, 0, networkByte + ripeHashLength);


            byte[] pkBytes = pubKey;
            ret1.T1PrivKeyHex = "";
            ret1.T1PubKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(pkBytes);
            ret1.T1PubKeyBin = GetBytesAsString(pkBytes);


            // 2 - SHA-256 hash of 1  (32 bytes)
            byte[] hash1 = sha256.ComputeHash(pkBytes);
            ret1.T2SHAKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(hash1);
            ret1.T2SHAKeyBin = GetBytesAsString(pkBytes);


            //3 - RIPEMD-160 Hash of 2  (20 bytes)     
            var ripeHash = ripe160.ComputeHash(hash1);
            ret1.T3SHAKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(ripeHash);
            ret1.T3SHAKeyBin = GetBytesAsString(ripeHash);

            //4 - Adding network bytes to 3 
            ripeHashNetwork[0] = 0x0;  // set the first bit accordingly
            Array.Copy(ripeHash, 0, ripeHashNetwork, 1, ripeHashLength);
            ret1.T4RIPEKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(ripeHashNetwork);
            ret1.T4RIPEKeyBin = GetBytesAsString(ripeHashNetwork);

            // 5 - SHA-256 hash of 4 //
            byte[] hash5 = sha256.ComputeHash(arraySegment1.ToStream(0, networkByte + ripeHashLength)); // 
            ret1.T5SHAKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(hash5);
            ret1.T5SHAKeyBin = GetBytesAsString(hash5);

            //6 - SHA-256 hash of 5  // 
            byte[] hash6 = sha256.ComputeHash(hash5); //  
            ret1.T6SHAKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(hash6);
            ret1.T6SHAKeyBin = GetBytesAsString(hash6);

            // 7 - First four bytes of 6 
            byte[] hash7 = new byte[4];
            Array.Copy(hash6, 0, ripeHashNetwork, networkByte + ripeHashLength, 4);
            Array.Copy(hash6, 0, hash7, 0, 4);
            ret1.T7CHKKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(hash7);
            ret1.T7CHKKeyBin = GetBytesAsString(hash7);

            //8 - Adding 7 at the end of 4 
            byte[] ripeHashNetworkChecksum = new byte[25];
            Array.Copy(ripeHashNetwork, ripeHashNetworkChecksum, ripeHashNetwork.Length);
            Array.Copy(hash6, 0, ripeHashNetworkChecksum, 21, 4);
            ret1.T8ALLKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(ripeHashNetworkChecksum);
            ret1.T8ALLKeyBin = GetBytesAsString(ripeHashNetworkChecksum);

            Buffer.BlockCopy(hash6, 0, ripeHashNetwork, networkByte + ripeHashLength, 4);
            Array.Reverse(ripeHashNetwork, 0, networkByte + ripeHashLength + 4);
            ret1.T9twoKeyHex = HexEncoderSO.ByteArrayToHexViaByteManipulation(ripeHashNetwork);
            ret1.T9twoKeyBin = GetBytesAsString(ripeHashNetwork);


            // Base58 encoding of ripeHashNetworkChecksum
            // Console.WriteLine(HexEncoder.ByteArrayToHexViaByteManipulation(ripeHashNetwork));
            // string sdf = GetBytesAsString(ripeHashNetwork);
            //Console.WriteLine();
            // BigInteger bi = System.Numerics.BigInteger.Parse(HexEncoder.ByteArrayToHexViaByteManipulation(ripeHashNetwork, 0, ripeHashLength
            //   + networkByte + 4), NumberStyles.HexNumber);

            //string b58 = Base58Check.EncodeBase58(bi);

            // BitConverter.GetBytes(

            BigInteger bi2 = new BigInteger(ripeHashNetwork);

            string b582 = Base58Check.EncodeBase58(bi2);

            // Console.WriteLine(b582 + Environment.NewLine + "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");

            // Byte to Hex string
            // ttp://stackoverflow.com/questions/623104/byte-to-hex-string
            ret1.T999Base58CheckOut = b582;

            if (doVerify)
            {
                var ret3 = Base58Check.DecodeBase58(b582);
                Base58Check.CheckBase58CheckTypo(b582);
                if (bi2 == ret3.BigInt)
                {
                    return ret1;
                }
                else
                {
                    // BUG IF THIS OCCURS
                    throw new DataMisalignedException("Verification failed");
                }
            }

            return ret1;
        }

        private static string GetBytesAsString(byte[] ripeHashNetwork)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var item in ripeHashNetwork)
            {
                sb.Append(item + ",");
            }
            string ret = sb.ToString();
            return ret.TrimEnd(",".ToCharArray());
        }


        public static String sBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        public static String EncodeBase58(BigInteger numberToShorten)
        {
            // WARNING: Beware of bignumber implementations that clip leading 0x00 bytes, or prepend extra 0x00 
            // bytes to indicate sign - your code must handle these cases properly or else you may generate valid-looking
            // addresses which can be sent to, but cannot be spent from - which would lead to the permanent loss of coins.)


            // Base58Check encoding is also used for encoding private keys in the Wallet Import Format. This is formed exactly
            // the same as a Bitcoin address, except that 0x80 is used for the version/application byte, and the payload is 32 bytes
            // instead of 20 (a private key in Bitcoin is a single 32-byte unsigned big-endian integer). Such encodings will always
            // yield a 51-character string that starts with '5', or more specifically, either '5H', '5J', or '5K'. 
            //  https://en.bitcoin.it/wiki/Base58Check_encoding

            const int sizeWalletImportFormat = 51;

            char[] result = new char[33];

            int i = 0;
            while (numberToShorten >= 0 && result.Length > i)
            {
                var lNumberRemainder = BigInteger.Remainder(numberToShorten, (BigInteger)sBase58Alphabet.Length);
                numberToShorten = numberToShorten / (BigInteger)sBase58Alphabet.Length;
                result[result.Length - 1 - i] = sBase58Alphabet[(int)lNumberRemainder];
                i++;
            }

            return new string(result);
        }
        public static DecodedBase58Result DecodeBase58(String base58StringToExpand)
        {
            DecodedBase58Result ret = new DecodedBase58Result();

            BigInteger lConverted = 0;
            BigInteger lTemporaryNumberConverter = 1;

            while (base58StringToExpand.Length > 0)
            {
                String sCurrentCharacter = base58StringToExpand.Substring(base58StringToExpand.Length - 1);
                int index = sBase58Alphabet.IndexOf(sCurrentCharacter);
                lConverted = lConverted + (lTemporaryNumberConverter * index);
                lTemporaryNumberConverter = lTemporaryNumberConverter * sBase58Alphabet.Length;
                base58StringToExpand = base58StringToExpand.Substring(0, base58StringToExpand.Length - 1);

                //  Unknown logic here... caller must make sure the decoded result has 25 bytes
                //if (base58StringToExpand.Length == 2)
                //    ret.LeadingZeros++;
                //else
                //    ret.LeadingZeros = 0;
            }

            ret.BigInt = lConverted;
            return ret;
        }

        // https://en.bitcoin.it/wiki/Mini_private_key_format
        public static bool CheckMiniPrivateKey(string p)
        {
            int CasasciusSeries1 = 22; // Discouraged due to security issues
            int MiniKey = 30; // Must support this length

            System.Security.Cryptography.SHA256 sha256 = new SHA256Managed();

            // Append a questionmark
            byte[] pkBytes = HexEncoderSO.ToByteArrayFromHex(p + "?");

            var hash = sha256.ComputeHash(pkBytes);

            // Does hash start with 00 (is well formed if so)
            // --- this is the private key

            return false;
        }
    }
    public class DecodedBase58Result
    {
        public int LeadingZeros { get; set; }
        public BigInteger BigInt { get; set; }
    }
}
