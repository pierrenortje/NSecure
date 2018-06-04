# NSecure <img src="https://travis-ci.org/pierrenortje/NSecure.svg?branch=master"/>
A library that allows two parties to exchange private key material over a public channel.


## Example:

```csharp
  string text = "Hello World!";

  var bob = new DiffieHellman();
  var sarah = new DiffieHellman();

  // Bob uses Sarah's public key to encrypt his message.
  byte[] secret = bob.Encrypt(sarah.PublicKey, text);

  // Sarah uses Bob's public key and her private key to decrypt the message.
  string decryptedMessage = sarah.Decrypt(bob.PublicKey, secret, bob.PrivateKey);
```
