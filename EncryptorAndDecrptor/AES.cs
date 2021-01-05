using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptorAndDecrptor
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.IO;
    using System.Security.Cryptography;


    public class AES
    {
        #region Object Variables        
        protected string hashAlgorithm;
        protected int passwordIterations;
        protected string initVector;
        protected int keySize;
        protected string passPhrase;
        protected string saltValue;
        #endregion

        public AES()
        {
            hashAlgorithm = "MD5"; // can be "SHA1"
            passwordIterations = 2;
            initVector = "@1B2c3D4e5F6g7H8";   // must be 16 bytes
            keySize = 256; // can be 192 or 128 
        }

        public string EncryptData(String plainText)
        {
            string EncryptedValue;
            passphrasesaltvalue();

            EncryptedValue = Encode(plainText, passPhrase, saltValue, hashAlgorithm, passwordIterations, initVector, keySize);
            return EncryptedValue;
        }

        public string DecryptData(String plainText)
        {
            string DecryptedValue;
            passphrasesaltvalue();

            DecryptedValue = Decode(plainText, passPhrase, saltValue, hashAlgorithm, passwordIterations, initVector, keySize);
            return DecryptedValue;
        }




        #region Encode
        private string Encode(string plainText, string passPhrase, string saltValue, string hashAlgorithm, int passwordIterations, string initVector, int keySize)
        {
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, saltValueBytes, hashAlgorithm, passwordIterations);
            byte[] keyBytes = password.GetBytes(keySize / 8);

            RijndaelManaged symmetricKey = new RijndaelManaged();

            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);

            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

            cryptoStream.FlushFinalBlock();

            byte[] cipherTextBytes = memoryStream.ToArray();

            memoryStream.Close();
            cryptoStream.Close();

            string cipherText = Convert.ToBase64String(cipherTextBytes);
            return cipherText;
        }
        #endregion

        #region Decode
        private string Decode(string cipherText, string passPhrase, string saltValue, string hashAlgorithm, int passwordIterations, string initVector, int keySize)
        {
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);


            PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, saltValueBytes, hashAlgorithm, passwordIterations);
            byte[] keyBytes = password.GetBytes(keySize / 8);

            RijndaelManaged symmetricKey = new RijndaelManaged();

            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);

            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

            memoryStream.Close();
            cryptoStream.Close();

            string plainText = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
            return plainText;
        }
        #endregion

        #region passphrasesaltvalue
        private void passphrasesaltvalue()
        {
            passPhrase = "TouchpointKP3605pr@se";
            saltValue = "TouchpointKP360s@1tValue";
        }
        #endregion


    }


}
