#region License
// Copyright (c) 2017 Pierre Nortje
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
#endregion

namespace NSecure.Encryption
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// A Diffie-Hellman implementation which allows two parties
    /// to exchange private key material over a public channel.
    /// </summary>
    public class DiffieHellman : IDisposable
    {
        #region Private Fields
        private Aes aes = null;
        private ECDiffieHellmanCng diffieHellman = null;

        private readonly byte[] publicKey;
        #endregion

        #region Constructor
        public DiffieHellman()
        {
            this.aes = new AesCryptoServiceProvider();

            this.diffieHellman = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };

            this.publicKey = this.diffieHellman.PublicKey.ToByteArray();
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Your public key.
        /// </summary>
        public byte[] PublicKey
        {
            get
            {
                return this.publicKey;
            }
        }

        /// <summary>
        /// Your private key.
        /// </summary>
        public byte[] PrivateKey
        {
            get
            {
                return this.aes.IV;
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Encrypts a message.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="secretMessage">The message to encrypt.</param>
        /// <returns>An encrypted byte array.</returns>
        public byte[] Encrypt(string publicKey, string secretMessage)
        {
            byte[] publicKeyByte = Encoding.UTF8.GetBytes(publicKey);
            return this.Encrypt(publicKey, secretMessage);
        }
        /// <summary>
        /// Encrypts a message.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="secretMessage">The message to encrypt.</param>
        /// <returns>An encrypted byte array.</returns>
        public byte[] Encrypt(byte[] publicKey, string secretMessage)
        {
            byte[] encryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var privateKey = this.diffieHellman.DeriveKeyMaterial(key);

            this.aes.Key = privateKey;

            using (var ciphertext = new MemoryStream())
            {
                using (ICryptoTransform encryptor = this.aes.CreateEncryptor())
                {
                    using (var cryptoStream = new CryptoStream(ciphertext, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] ciphertextMessage = Encoding.UTF8.GetBytes(secretMessage);
                        cryptoStream.Write(ciphertextMessage, 0, ciphertextMessage.Length);
                    }
                }

                encryptedMessage = ciphertext.ToArray();
            }

            return encryptedMessage;
        }
        /// <summary>
        /// Encrypts a message as an asynchronous operation.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="secretMessage">The message to encrypt.</param>
        /// <returns>An encrypted byte array.</returns>
        public async Task<byte[]> EncryptAsync(string publicKey, string secretMessage)
        {
            byte[] publicKeyByte = Encoding.UTF8.GetBytes(publicKey);
            return await this.EncryptAsync(publicKey, secretMessage);
        }
        /// <summary>
        /// Encrypts a message as an asynchronous operation.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="secretMessage">The message to encrypt.</param>
        /// <returns>An encrypted byte array.</returns>
        public async Task<byte[]> EncryptAsync(byte[] publicKey, string secretMessage)
        {
            byte[] encryptedResult;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var privateKey = this.diffieHellman.DeriveKeyMaterial(key);

            this.aes.Key = privateKey;

            using (var ciphertext = new MemoryStream())
            {
                using (ICryptoTransform encryptor = this.aes.CreateEncryptor())
                {
                    using (var cryptoStream = new CryptoStream(ciphertext, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] ciphertextMessage = Encoding.UTF8.GetBytes(secretMessage);
                        await cryptoStream.WriteAsync(ciphertextMessage, 0, ciphertextMessage.Length);
                    }
                }

                encryptedResult = ciphertext.ToArray();
            }

            return encryptedResult;
        }

        /// <summary>
        /// Decrypts an encrypted message.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="encryptedMessage">The message to decrypt.</param>
        /// <param name="privateKey">Your private key.</param>
        /// <returns>A decrypted message.</returns>
        public string Decrypt(string publicKey, byte[] encryptedMessage, byte[] privateKey)
        {
            byte[] publicKeyByte = Encoding.UTF8.GetBytes(publicKey);
            return this.Decrypt(publicKeyByte, encryptedMessage, privateKey);
        }
        /// <summary>
        /// Decrypts an encrypted message.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="encryptedMessage">The message to decrypt.</param>
        /// <param name="privateKey">Your private key.</param>
        /// <returns>A decrypted message.</returns>
        public string Decrypt(string publicKey, string encryptedMessage, byte[] privateKey)
        {
            byte[] publicKeyByte = Encoding.UTF8.GetBytes(publicKey);
            byte[] encryptedMessageKeyByte = Encoding.UTF8.GetBytes(encryptedMessage);
            return this.Decrypt(publicKeyByte, encryptedMessageKeyByte, privateKey);
        }
        /// <summary>
        /// Decrypts an encrypted message.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="encryptedMessage">The message to decrypt.</param>
        /// <param name="privateKey">Your private key.</param>
        /// <returns>A decrypted message.</returns>
        public string Decrypt(byte[] publicKey, byte[] encryptedMessage, byte[] privateKey)
        {
            string decryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var derivedKey = this.diffieHellman.DeriveKeyMaterial(key);

            this.aes.Key = derivedKey;
            this.aes.IV = privateKey;

            using (var plaintext = new MemoryStream())
            {
                using (ICryptoTransform decryptor = this.aes.CreateDecryptor())
                {
                    using (var cryptoStream = new CryptoStream(plaintext, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedMessage, 0, encryptedMessage.Length);
                    }
                }

                decryptedMessage = Encoding.UTF8.GetString(plaintext.ToArray());
            }

            return decryptedMessage;
        }
        /// <summary>
        /// Decrypts an encrypted message as an asynchronous operation.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="encryptedMessage">The message to decrypt.</param>
        /// <param name="privateKey">Your private key.</param>
        /// <returns>A decrypted message.</returns>
        public async Task<string> DecryptAsync(string publicKey, byte[] encryptedMessage, byte[] privateKey)
        {
            byte[] publicKeyByte = Encoding.UTF8.GetBytes(publicKey);
            return await this.DecryptAsync(publicKeyByte, encryptedMessage, privateKey);
        }
        /// <summary>
        /// Decrypts an encrypted message as an asynchronous operation.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="encryptedMessage">The message to decrypt.</param>
        /// <param name="privateKey">Your private key.</param>
        /// <returns>A decrypted message.</returns>
        public async Task<string> DecryptAsync(string publicKey, string encryptedMessage, byte[] privateKey)
        {
            byte[] publicKeyByte = Encoding.UTF8.GetBytes(publicKey);
            byte[] encryptedMessageKeyByte = Encoding.UTF8.GetBytes(encryptedMessage);
            return await this.DecryptAsync(publicKeyByte, encryptedMessageKeyByte, privateKey);
        }
        /// <summary>
        /// Decrypts an encrypted message as an asynchronous operation.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="encryptedMessage">The message to decrypt.</param>
        /// <param name="privateKey">Your private key.</param>
        /// <returns>A decrypted message.</returns>
        public async Task<string> DecryptAsync(byte[] publicKey, byte[] encryptedMessage, byte[] privateKey)
        {
            string decryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var derivedKey = this.diffieHellman.DeriveKeyMaterial(key);

            this.aes.Key = derivedKey;
            this.aes.IV = privateKey;

            using (var plaintext = new MemoryStream())
            {
                using (ICryptoTransform decryptor = this.aes.CreateDecryptor())
                {
                    using (var cryptoStream = new CryptoStream(plaintext, decryptor, CryptoStreamMode.Write))
                    {
                        await cryptoStream.WriteAsync(encryptedMessage, 0, encryptedMessage.Length);
                    }
                }

                decryptedMessage = Encoding.UTF8.GetString(plaintext.ToArray());
            }

            return decryptedMessage;
        }
        #endregion

        #region IDisposable Members
        public void Dispose()
        {
            if (this.aes != null)
            {
                this.aes.Dispose();
                this.aes = null;
            }

            if (this.diffieHellman != null)
            {
                this.diffieHellman.Dispose();
                this.diffieHellman = null;
            }
        }
        #endregion
    }
}