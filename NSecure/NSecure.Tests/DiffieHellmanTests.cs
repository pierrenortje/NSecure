using NSecure.Encryption;
using NUnit.Framework;

namespace NSecure.Tests
{
    [TestFixture]
    public class DiffieHellmanTests
    {
        [TestCase]
        public void Encrypt_Decrypt()
        {
            string text = "Hello World!";

            var bob = new DiffieHellman();
            var sarah = new DiffieHellman();

            // Bob uses Sarah's public key to encrypt his message.
            byte[] secret = bob.Encrypt(sarah.PublicKey, text);

            // Sarah uses Bob's public key and her private key to decrypt the message.
            string decryptedMessage = sarah.Decrypt(bob.PublicKey, secret, bob.PrivateKey);
        }
    }
}
