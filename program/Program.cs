using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class AesEncryptor
{
    // Method to generate an AES key
    public static byte[] GenerateAesKey(int keySize = 256)
    {
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = keySize;
            aes.GenerateKey();
            return aes.Key;
        }
    }

    // Method to encrypt a file using AES
    public static byte[] EncryptFileWithAes(string filePath, byte[] aesKey, out byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.GenerateIV();
            iv = aes.IV;

            using (FileStream inputFileStream = new FileStream(filePath, FileMode.Open))
            using (MemoryStream outputMemoryStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(outputMemoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                inputFileStream.CopyTo(cryptoStream);
                cryptoStream.FlushFinalBlock();
                return outputMemoryStream.ToArray();
            }
        }
    }

    // Method to encrypt the AES key using RSA
    public static byte[] EncryptAesKeyWithRsa(byte[] aesKey, RSA rsa)
    {
        return rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
    }

    // Method to load an RSA public key from a .pem file
    public static RSA LoadPublicKeyFromPem(string pemFilePath)
    {
        string pemContent = File.ReadAllText(pemFilePath);
        byte[] publicKeyBytes = Convert.FromBase64String(pemContent
            .Replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .Replace("-----END RSA PUBLIC KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", ""));
        RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKeyBytes, out _);
        return rsa;
    }
}
public class Program
{
    public static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "aes-key")
        {
            // Generate the AES key
            byte[] aesKey = AesEncryptor.GenerateAesKey();
            Console.WriteLine("Generated AES Key (Base64): " + Convert.ToBase64String(aesKey));

            // Save the AES key to a .bin file
            string aesKeyFilePath = Path.Combine(Directory.GetCurrentDirectory(), "aesKey.bin");
            File.WriteAllBytes(aesKeyFilePath, aesKey);
            Console.WriteLine("AES Key saved to: " + aesKeyFilePath);
        }
        else if (args.Length > 2 && args[0] == "encrypt")
         {
            // Encrypt the file using AES and encrypt the AES key with RSA
            string filePath = args[1];
            string publicKeyPath = args[2];
            string aesKeyPath = args[3];
        
            // Read AES key from .bin file
            byte[] aesKey = File.ReadAllBytes(aesKeyPath);
            byte[] iv;
        
            // Encrypt the file with AES
            byte[] encryptedFileData = AesEncryptor.EncryptFileWithAes(filePath, aesKey, out iv);
        
            // Encrypt the AES key with RSA
            using (RSA rsa = AesEncryptor.LoadPublicKeyFromPem(publicKeyPath))
            {
                byte[] encryptedAesKey = AesEncryptor.EncryptAesKeyWithRsa(aesKey, rsa);
                Console.WriteLine(encryptedAesKey.ToString());
                // Save the encrypted file and encrypted AES key
                string outputFilePath = Path.ChangeExtension(filePath, ".bin");
                Console.WriteLine("Encrypted file path:"  + outputFilePath);
                File.WriteAllBytes(outputFilePath, encryptedFileData);
        
                string encryptedKeyFilePath = Path.Combine(Path.GetDirectoryName(filePath) ?? string.Empty, Path.GetFileNameWithoutExtension(filePath) + "AesKey.bin");
                File.WriteAllBytes(encryptedKeyFilePath, encryptedAesKey);
        
                string ivFilePath = Path.ChangeExtension(filePath, ".iv");
                File.WriteAllBytes(ivFilePath, iv);
        
                Console.WriteLine("File encrypted successfully:");
                Console.WriteLine("  Encrypted File: " + outputFilePath);
                Console.WriteLine("  Encrypted AES Key: " + encryptedKeyFilePath);
                Console.WriteLine("  AES IV: " + ivFilePath);
            }
        }
        else
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  To generate an AES key: dotnet run -- aes-key");
            Console.WriteLine("  To encrypt a file: dotnet run -- encrypt <file-path> <public-key.pem> <aes-key.bin>");
        }
    }
}