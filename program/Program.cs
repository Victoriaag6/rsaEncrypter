using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.WriteLine("❌ Por favor, proporciona la ruta del archivo de entrada, la ruta del archivo de la clave AES y la ruta del archivo de la clave pública RSA como argumentos.");
            return;
        }

        string inputFilePath = args[0];
        string aesKeyFilePath = args[1];
        string publicKeyFilePath = args[2];
        string encryptedFilePath = "licitacion_encrypted.bin";
        string encryptedKeyFilePath = "aes_key_encrypted.bin";

        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("📄 🔐 SISTEMA DE ENCRIPTACIÓN PARA LICITACIONES 🔐 📄\n");

        // Leer el contenido del archivo
        string fileContent;
        try
        {
            fileContent = File.ReadAllText(inputFilePath, Encoding.UTF8);
            Console.WriteLine(fileContent);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error al leer el archivo: {ex.Message}");
            return;
        }
        Console.WriteLine("📄 Contenido del Archivo Antes de Encriptar:\n" + fileContent + "\n");

        // Leer la clave AES desde el archivo
        byte[] aesKey;
        try
        {
            aesKey = Convert.FromBase64String(File.ReadAllText(aesKeyFilePath));
            Console.WriteLine("🔑 Clave Privada (AES) leída desde el archivo.\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error al leer la clave AES: {ex.Message}");
            return;
        }

        // Generar IV
        byte[] aesIV = GenerateAESIV();
        Console.WriteLine("IV Generado: " + Convert.ToBase64String(aesIV) + "\n");

        // Cifrar el archivo con AES
        byte[] encryptedContent = EncryptAES(fileContent, aesKey, aesIV);

        // Guardar el contenido encriptado en un archivo
        try
        {
            File.WriteAllBytes(encryptedFilePath, encryptedContent);
            Console.WriteLine("✅ Archivo encriptado guardado en 'licitacion_encrypted.txt'.\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error al guardar el archivo encriptado: {ex.Message}");
            return;
        }

        // Leer la clave pública RSA desde el archivo
        string publicKey;
        try
        {
            publicKey = File.ReadAllText(publicKeyFilePath);
            Console.WriteLine("🗝️ Clave Pública (RSA) leída desde el archivo.\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error al leer la clave pública RSA: {ex.Message}");
            return;
        }

        // Encriptar la clave AES con la clave pública de RSA
        byte[] encryptedAESKey = EncryptRSA(aesKey, publicKey);

        // Guardar la clave AES encriptada en un archivo
        try
        {
            File.WriteAllBytes(encryptedKeyFilePath, encryptedAESKey);
            Console.WriteLine("✅ Clave AES encriptada guardada en 'aes_key_encrypted.txt'.\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error al guardar la clave AES encriptada: {ex.Message}");
            return;
        }
    }

    // Método para generar IV
    static byte[] GenerateAESIV()
    {
        using Aes aes = Aes.Create();
        aes.GenerateIV();
        return aes.IV;
    }

    // Método para encriptar con AES
    static byte[] EncryptAES(string plainText, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using MemoryStream ms = new();
        using CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        using StreamWriter sw = new(cs);

        sw.Write(plainText);
        sw.Flush();
        cs.FlushFinalBlock();
        return ms.ToArray();
    }

    // Método para encriptar con RSA (usa la clave pública del servidor)
    static byte[] EncryptRSA(byte[] data, string publicKey)
    {
        using RSACryptoServiceProvider rsa = new(2048);
        rsa.FromXmlString(publicKey);
        return rsa.Encrypt(data, false);
    }
}