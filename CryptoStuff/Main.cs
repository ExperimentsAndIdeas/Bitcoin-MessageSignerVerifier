using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System.Security.Cryptography;
using System.Text;
using System;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Bitnet.Client.Encoder;
using Bitnet.Client;

public class Bitcoin
{ 

    // http://stackoverflow.com/questions/19665491/how-do-i-get-an-ecdsa-public-key-from-just-a-bitcoin-signature-sec1-4-1-6-k
    public static void FullSignatureTest(byte[] hash)
    {
        X9ECParameters ecParams = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
        ECDomainParameters domainParameters = new ECDomainParameters(ecParams.Curve,
                                                                     ecParams.G, ecParams.N, ecParams.H,
                                                                     ecParams.GetSeed());
        ECKeyGenerationParameters keyGenParams =
          new ECKeyGenerationParameters(domainParameters, new SecureRandom());

        AsymmetricCipherKeyPair keyPair;
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.Init(keyGenParams);
        keyPair = generator.GenerateKeyPair();

        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.Private;
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters)keyPair.Public;

        Console.WriteLine("Generated private key: " + ToHex(privateKey.D.ToByteArrayUnsigned()));
        Console.WriteLine("Generated public key: " + ToHex(publicKey.Q.GetEncoded()));

        ECDsaSigner signer = new ECDsaSigner();
        signer.Init(true, privateKey);
        BigInteger[] sig = signer.GenerateSignature(hash);

        int recid = -1;
        for (int rec = 0; rec < 4; rec++)
        {
            try
            {
                ECPoint Q = ECDSA_SIG_recover_key_GFp(sig, hash, rec, true);
                if (ToHex(publicKey.Q.GetEncoded()).Equals(ToHex(Q.GetEncoded())))
                {
                    recid = rec;
                    break;
                }
            }
            catch (Exception)
            {
                continue;
            }
        }
        if (recid < 0) throw new Exception("Did not find proper recid");

        byte[] fullSigBytes = new byte[65];
        fullSigBytes[0] = (byte)(27 + recid);
        Buffer.BlockCopy(sig[0].ToByteArrayUnsigned(), 0, fullSigBytes, 1, 32);
        Buffer.BlockCopy(sig[1].ToByteArrayUnsigned(), 0, fullSigBytes, 33, 32);

        Console.WriteLine("Generated full signature: " + Convert.ToBase64String(fullSigBytes));

        byte[] sigBytes = new byte[64];
        Buffer.BlockCopy(sig[0].ToByteArrayUnsigned(), 0, sigBytes, 0, 32);
        Buffer.BlockCopy(sig[1].ToByteArrayUnsigned(), 0, sigBytes, 32, 32);

        ECPoint genQ = ECDSA_SIG_recover_key_GFp(sig, hash, recid, false);
        Console.WriteLine("Generated signature verifies: " + VerifySignature(genQ.GetEncoded(), hash, sigBytes));
    }

    public static ECPoint Recover(byte[] hash, byte[] sigBytes, int rec)
    {
        BigInteger r = new BigInteger(1, sigBytes, 0, 32);
        BigInteger s = new BigInteger(1, sigBytes, 32, 32);
        BigInteger[] sig = new BigInteger[] { r, s };
        ECPoint Q = ECDSA_SIG_recover_key_GFp(sig, hash, rec, true);
        return Q;
    }

    public static ECPoint ECDSA_SIG_recover_key_GFp(BigInteger[] sig, byte[] hash, int recid, bool check)
    {
        X9ECParameters ecParams = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
        int i = recid / 2;

        Console.WriteLine("r: " + ToHex(sig[0].ToByteArrayUnsigned()));
        Console.WriteLine("s: " + ToHex(sig[1].ToByteArrayUnsigned()));

        BigInteger order = ecParams.N;
        BigInteger field = (ecParams.Curve as FpCurve).Q;
        BigInteger x = order.Multiply(new BigInteger(i.ToString())).Add(sig[0]);
        if (x.CompareTo(field) >= 0) throw new Exception("X too large");

        Console.WriteLine("Order: " + ToHex(order.ToByteArrayUnsigned()));
        Console.WriteLine("Field: " + ToHex(field.ToByteArrayUnsigned()));

        byte[] compressedPoint = new Byte[x.ToByteArrayUnsigned().Length + 1];
        compressedPoint[0] = (byte)(0x02 + (recid % 2));
        Buffer.BlockCopy(x.ToByteArrayUnsigned(), 0, compressedPoint, 1, compressedPoint.Length - 1);
        ECPoint R = ecParams.Curve.DecodePoint(compressedPoint);

        Console.WriteLine("R: " + ToHex(R.GetEncoded()));

        if (check)
        {
            ECPoint O = R.Multiply(order);
            if (!O.IsInfinity) throw new Exception("Check failed");
        }

        int n = (ecParams.Curve as FpCurve).Q.ToByteArrayUnsigned().Length * 8;
        BigInteger e = new BigInteger(1, hash);
        if (8 * hash.Length > n)
        {
            e = e.ShiftRight(8 - (n & 7));
        }
        e = BigInteger.Zero.Subtract(e).Mod(order);
        BigInteger rr = sig[0].ModInverse(order);
        BigInteger sor = sig[1].Multiply(rr).Mod(order);
        BigInteger eor = e.Multiply(rr).Mod(order);
        ECPoint Q = ecParams.G.Multiply(eor).Add(R.Multiply(sor));

        Console.WriteLine("n: " + n);
        Console.WriteLine("e: " + ToHex(e.ToByteArrayUnsigned()));
        Console.WriteLine("rr: " + ToHex(rr.ToByteArrayUnsigned()));
        Console.WriteLine("sor: " + ToHex(sor.ToByteArrayUnsigned()));
        Console.WriteLine("eor: " + ToHex(eor.ToByteArrayUnsigned()));
        Console.WriteLine("Q: " + ToHex(Q.GetEncoded()));

        return Q;
    }

    public static bool VerifySignature(byte[] pubkey, byte[] hash, byte[] sigBytes)
    {
        X9ECParameters ecParams = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
        ECDomainParameters domainParameters = new ECDomainParameters(ecParams.Curve,
                                                                     ecParams.G, ecParams.N, ecParams.H,
                                                                     ecParams.GetSeed());

        BigInteger r = new BigInteger(1, sigBytes, 0, 32);
        BigInteger s = new BigInteger(1, sigBytes, 32, 32);
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(ecParams.Curve.DecodePoint(pubkey), domainParameters);

        ECDsaSigner signer = new ECDsaSigner();
        signer.Init(false, publicKey);
        return signer.VerifySignature(hash, r, s);
    }
     

    public static void Main()
    {
       string msg = "test123";
       string sig = "ICHD2obqklY8dVBvjwwiDL3c7QkOnOif0tRlbcM+uk7vnuA0LZu6mVsKMx3Nvk7vdiV28cHO7IRuqXwzO3A3m3A=";
        string hashb58 = "15NGbNHePvuxKJrSV7Qy7Z9pKjxJDo39nV";


        SHA256Managed sha256 = new SHA256Managed();
        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(msg), 0, Encoding.UTF8.GetByteCount(msg));
        Console.WriteLine("Hash: " + ToHex(hash));

        byte[] tmpBytes = Convert.FromBase64String(sig);
        byte[] sigBytes = new byte[tmpBytes.Length - 1];
        Buffer.BlockCopy(tmpBytes, 1, sigBytes, 0, sigBytes.Length);

        int rec = (tmpBytes[0] - 27) & ~4;
        Console.WriteLine("Rec {0}", rec);

        ECPoint Q = Recover(hash, sigBytes, rec);
        string qstr = ToHex(Q.GetEncoded());
        string qstr1 = ByteArrayToHexViaByteManipulation(Q.GetEncoded(), 0, Q.GetEncoded().Length);
        //Console.WriteLine("Q is same as supplied: " + qstr.Equals(pubkey));

        //Console.WriteLine("Signature verified correctly: " + VerifySignature(Q.GetEncoded(), hash, sigBytes));

        byte[] publicKey = HexEncoderSO.ToByteArrayFromHex(qstr1);
        string hashedExtractedKey = HexEncoderSO.ByteArrayToHexViaByteManipulation(publicKey);
        bool doVerify = true;
        var result = Base58Check.EncodePKToBase58Check1(publicKey, doVerify);

        if (result.T999Base58CheckOut != hashb58)
        {
            Console.WriteLine("Extracted key: {0} does not match reference value {1}", result.T999Base58CheckOut, hashb58);
        }
        else
        {
            Console.WriteLine(  "Hashes match {0}", hashb58);
        }
        Console.ReadKey();
    }

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
    public static string ToHex(byte[] data)
    {
        return BitConverter.ToString(data).Replace("-", "");
    }
}