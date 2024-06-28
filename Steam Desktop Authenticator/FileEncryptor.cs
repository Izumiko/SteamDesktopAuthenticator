using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace Steam_Desktop_Authenticator
{
    /// <summary>
    /// This class provides the controls that will encrypt and decrypt the *.maFile files
    /// 
    /// Passwords entered will be passed into 100k rounds of PBKDF2 (RFC2898) with a cryptographically random salt.
    /// The generated key will then be passed into AES-256 (RijndalManaged) which will encrypt the data
    /// in cypher block chaining (CBC) mode, and then write both the PBKDF2 salt and encrypted data onto the disk.
    /// </summary>
    public static class FileEncryptor
    {
        private const int PBKDF2_ITERATIONS = 50000; //Set to 50k to make program not unbearably slow. May increase in future.
        private const int SALT_LENGTH = 8;
        private const int KEY_SIZE_BYTES = 32;
        private const int IV_LENGTH = 16;

        /// <summary>
        /// Returns an 8-byte cryptographically random salt in base64 encoding
        /// </summary>
        /// <returns>A base64 encoded string representing the random salt</returns>
        public static string GetRandomSalt()
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SALT_LENGTH);
            return Convert.ToBase64String(salt);
        }

        /// <summary>
        /// Returns a 16-byte cryptographically random initialization vector (IV) in base64 encoding
        /// </summary>
        /// <returns>A base64 encoded string representing the random initialization vector</returns>
        public static string GetInitializationVector()
        {
            byte[] IV = RandomNumberGenerator.GetBytes(IV_LENGTH);
            return Convert.ToBase64String(IV);
        }


        /// <summary>
        /// Generates an encryption key derived using a password, a random salt, and specified number of rounds of PBKDF2
        /// </summary>
        /// <param name="password">The password to derive the key from</param>
        /// <param name="salt">The salt as a base64 encoded string</param>
        /// <returns>A byte array representing the derived encryption key</returns>
        /// <exception cref="ArgumentException">Thrown when password or salt is null or empty</exception>
        private static byte[] GetEncryptionKey(string password, string salt)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is empty", nameof(password));
            }
            if (string.IsNullOrEmpty(salt))
            {
                throw new ArgumentException("Salt is empty", nameof(salt));
            }

            byte[] saltBytes = Convert.FromBase64String(salt);
            return Rfc2898DeriveBytes.Pbkdf2(
                password,
                saltBytes,
                PBKDF2_ITERATIONS,
                HashAlgorithmName.SHA256,
                KEY_SIZE_BYTES);
        }

        /// <summary>
        /// Tries to decrypt and return data given an encrypted base64 encoded string. Must use the same
        /// password, salt, IV, and ciphertext that was used during the original encryption of the data.
        /// </summary>
        /// <param name="password">The password used for encryption</param>
        /// <param name="passwordSalt">The salt used for key derivation</param>
        /// <param name="iv">Initialization Vector</param>
        /// <param name="encryptedData">The encrypted data as a base64 encoded string</param>
        /// <returns>The decrypted string, or null if decryption fails</returns>
        /// <exception cref="ArgumentException">Thrown when any input parameter is null or empty</exception>
        public static string DecryptData(string password, string passwordSalt, string iv, string encryptedData)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password is empty", nameof(password));
            if (string.IsNullOrEmpty(passwordSalt))
                throw new ArgumentException("Salt is empty", nameof(passwordSalt));
            if (string.IsNullOrEmpty(iv))
                throw new ArgumentException("Initialization Vector is empty", nameof(iv));
            if (string.IsNullOrEmpty(encryptedData))
                throw new ArgumentException("Encrypted data is empty", nameof(encryptedData));


            byte[] cipherText = Convert.FromBase64String(encryptedData);
            byte[] key = GetEncryptionKey(password, passwordSalt);
            byte[] ivBytes = Convert.FromBase64String(iv);

            try
            {
                using var aes = Aes.Create();
                aes.Key = key;
                aes.IV = ivBytes;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using var msDecrypt = new MemoryStream(cipherText);
                using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8);

                return srDecrypt.ReadToEnd();
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        /// <summary>
        /// Encrypts a string given a password, salt, and initialization vector, then returns result in base64 encoded string.
        /// 
        /// To retrieve this data, you must decrypt with the same password, salt, IV, and cyphertext that was used during encryption
        /// </summary>
        /// <param name="password">The password used for encryption</param>
        /// <param name="passwordSalt">The salt used for key derivation</param>
        /// <param name="iv">Initialization Vector</param>
        /// <param name="plaintext">The text to be encrypted</param>
        /// <returns>The encrypted data as a base64 encoded string</returns>
        /// <exception cref="ArgumentException">Thrown when any input parameter is null or empty</exception>
        public static string EncryptData(string password, string passwordSalt, string iv, string plaintext)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password is empty", nameof(password));
            if (string.IsNullOrEmpty(passwordSalt))
                throw new ArgumentException("Salt is empty", nameof(passwordSalt));
            if (string.IsNullOrEmpty(iv))
                throw new ArgumentException("Initialization Vector is empty", nameof(iv));
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("Plaintext data is empty", nameof(plaintext));

            byte[] key = GetEncryptionKey(password, passwordSalt);
            byte[] ivBytes = Convert.FromBase64String(iv);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = ivBytes;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (var swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
            {
                swEncrypt.Write(plaintext);
            }

            byte[] ciphertext = msEncrypt.ToArray();
            return Convert.ToBase64String(ciphertext);
        }
    }
}
