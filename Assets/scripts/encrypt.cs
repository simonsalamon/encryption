using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

public class encrypt
{



    public static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptData(string plainText , byte[] key)
    {
        
        using (var aes = new AesGcm(key))
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];

            RandomNumberGenerator.Fill(nonce);

            var cipher = new byte[plaintextBytes.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            aes.Encrypt(nonce, plaintextBytes, cipher, tag);

            return (cipher, nonce, tag);
        }
    }


    public static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptData(byte[] plaintextBytes  , byte[] key)
    {
        using(var aes = new AesGcm(key))
        {

            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);

            var cipher = new byte[plaintextBytes.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            aes.Encrypt(nonce,plaintextBytes ,cipher, tag);

            return (cipher, nonce, tag);
        }
    }


    public static string Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag , byte[] key)
    {
        using (var aes = new AesGcm(key))
        {
            var plaintextBytes = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }


}