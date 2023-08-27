using Org.BouncyCastle.Crypto.Parameters;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;

public class test : MonoBehaviour
{

    private byte[] key;

    // Start is called before the first frame update
    void Start()
    {
        createKey();

        //var (ciphertext, nonce, tag) = encrypt.EncryptData("hi dadash " , key);


        //Debug.Log(Encoding.UTF8.GetString(ciphertext));

        //var text = encrypt.Decrypt(ciphertext, nonce, tag , key);

        //Debug.Log(text);



        var(ciphertext, nonce, tag) = newEncrypt.EncryptWithBouncyCastle( "سلام داداش ", key);
        Debug.Log(Encoding.UTF8.GetString(ciphertext));


        string encrypedData = newEncrypt.DecryptWithBouncyCastle(ciphertext , nonce , tag , key);

        Debug.Log(encrypedData);

    }

    public void createKey()
    {

        key = new byte[32];
        RandomNumberGenerator.Fill(key);
    }
}
