using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoStuff
{
    class Program
    {
        static void Mains(string[] args)
        {
            BrowserIDTests();
        }

        private static void BrowserIDTests()
        {

            // RSAKeyPairGenerator generates the RSA Key pair based on the random number and strength of key required
            RsaKeyPairGenerator rsaKeyPairGnr = new RsaKeyPairGenerator();
            rsaKeyPairGnr.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 512));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair = rsaKeyPairGnr.GenerateKeyPair();

            // Extracting the public key from the pair
            RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;
 

            readPrivateKey(@"c:\temp\public-key.pem");
        }
        static AsymmetricKeyParameter readPrivateKey(string privateKeyFileName)
        {
            // openssl genrsa -out private-key.pem 2048
            // openssl rsa -in private-key.pem -pubout > public-key.pem
            // Now read the file with this:
      
             RsaKeyParameters keyPair;

            using (var reader = File.OpenText(privateKeyFileName))
            {
                var data = new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
                // Note - there are two pemreaders to choose from....
                keyPair = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)data;
                 
            } 

           string json  = string.Format(@"{
    ""public-key"": {
""algorithm"": ""RS"" ,
""n"": ""{0}"",
""e"": ""{1}"" },
""authentication"": ""{2}"", 
""provisioning"": ""{3}""}", keyPair.Modulus, keyPair.Exponent, "/browserid/sign_in.html", "/browserid/provision.html");

            Console.WriteLine(json);
            return keyPair;
        }
        public static byte[] Decrypt3(byte[] data, string pemFilename)
        {
            string result = "";
            try
            {
                AsymmetricKeyParameter key = readPrivateKey(pemFilename);

                RsaEngine e = new RsaEngine();

                e.Init(false, key);
                //byte[] cipheredBytes = GetBytes(encryptedMsg);

                //Debug.Log (encryptedMsg);

                byte[] cipheredBytes = e.ProcessBlock(data, 0, data.Length);
                //result = Encoding.UTF8.GetString(cipheredBytes);
                //return result;
                return cipheredBytes;

            }
            catch (Exception e)
            {
                System.Text.UTF8Encoding enc = new UTF8Encoding();
                
                Debug.Write("Exception in Decrypt3: " + e.Message);
                return enc.GetBytes(e.Message);
            }
        }
        public String Sign(String data, String privateModulusHexString, String privateExponentHexString)
        {
            /* Make the key */
            RsaKeyParameters key = MakeKey(privateModulusHexString, privateExponentHexString, true);

            /* Init alg */
            ISigner sig = SignerUtilities.GetSigner("SHA1withRSA");

            /* Populate key */
            sig.Init(true, key);

            /* Get the bytes to be signed from the string */
            var bytes = Encoding.UTF8.GetBytes(data);

            /* Calc the signature */
            sig.BlockUpdate(bytes, 0, bytes.Length);
            byte[] signature = sig.GenerateSignature();

            /* Base 64 encode the sig so its 8-bit clean */
            var signedString = Convert.ToBase64String(signature);

            return signedString;
        }

        public bool Verify(String data, String expectedSignature, String publicModulusHexString, String publicExponentHexString)
        {
            /* Make the key */
            RsaKeyParameters key = MakeKey(publicModulusHexString, publicExponentHexString, false);

            /* Init alg */
            ISigner signer = SignerUtilities.GetSigner("SHA1withRSA");

            /* Populate key */
            signer.Init(false, key);

            /* Get the signature into bytes */
            var expectedSig = Convert.FromBase64String(expectedSignature);

            /* Get the bytes to be signed from the string */
            var msgBytes = Encoding.UTF8.GetBytes(data);

            /* Calculate the signature and see if it matches */
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
            return signer.VerifySignature(expectedSig);
        }

        private RsaKeyParameters MakeKey(String modulusHexString, String exponentHexString, bool isPrivateKey)
        {
            var modulus = new Org.BouncyCastle.Math.BigInteger(modulusHexString, 16);
            var exponent = new Org.BouncyCastle.Math.BigInteger(exponentHexString, 16);

            return new RsaKeyParameters(isPrivateKey, modulus, exponent);
        }
    }
}
