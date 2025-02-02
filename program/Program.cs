using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("📄 🔐 SISTEMA DE ENCRIPTACIÓN PARA LICITACIONES 🔐 📄\n");

        // Rutas de los archivos
        string inputFilePath = "licitacion.txt";
        string encryptedFilePath = "licitacion_encrypted.txt";
        string encryptedKeyFilePath = "aes_key_encrypted.txt";

        // Escribir contenido al archivo
        try
        {
            File.WriteAllText(inputFilePath, "funciona 20 seguro mis amores", Encoding.UTF8);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error al escribir en el archivo: {ex.Message}");
            return;
        }

        // Leer el contenido del archivo
        string fileContent = File.ReadAllText(inputFilePath, Encoding.UTF8);

        // Generar clave AES y IV
        using Aes aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();
        byte[] aesKey = aes.Key;
        byte[] aesIV = aes.IV;

        Console.WriteLine("🔑 Clave AES Generada: " + Convert.ToBase64String(aesKey));
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

        // Generar claves RSA
        using RSACryptoServiceProvider rsa = new(2048);
        string publicKey = rsa.ToXmlString(false); // Clave pública
        string privateKey = rsa.ToXmlString(true); // Clave privada

        Console.WriteLine("🗝️ Clave Pública (RSA):\n" + publicKey + "\n");

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
