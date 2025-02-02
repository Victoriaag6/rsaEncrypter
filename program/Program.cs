using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("📄 🔐 === SISTEMA DE ENCRIPTACIÓN PARA LICITACIONES === 🔐 📄\n");

        string inputFilePath = "licitacion.txt";
        string encryptedFilePath = "licitacion_encrypted.txt";

        //clave AES y un IV (vector de inicialización)
        using Aes aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();
        byte[] aesKey = aes.Key;
        byte[] aesIV = aes.IV;

        Console.WriteLine("🔑 Clave AES Generada: " + Convert.ToBase64String(aesKey));
        Console.WriteLine("🛠️ IV Generado: " + Convert.ToBase64String(aesIV) + "\n");

        //Leer el contenido del archivo a encriptar
        if (!File.Exists(inputFilePath))
        {
            Console.WriteLine("⚠️ El archivo 'licitacion.txt' no existe. Creando archivo de prueba...");
            File.WriteAllText(inputFilePath, "Este es el contenido de la licitación confidencial.");
        }
        string fileContent = File.ReadAllText(inputFilePath);
        Console.WriteLine("📄 Contenido Original del Archivo:\n" + fileContent + "\n");

        //Cifrar el contenido del archivo con AES
        byte[] encryptedContent = EncryptAES(fileContent, aesKey, aesIV);

        //Guardar el contenido encriptado en un archivo
        try
        {
            File.WriteAllBytes(encryptedFilePath, encryptedContent);
            Console.WriteLine("✅ Archivo encriptado guardado en 'licitacion_encrypted.txt'.\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error al guardar el archivo encriptado: {ex.Message}");
        }

        //Mostrar el contenido encriptado en Base64 (para verificar)
        Console.WriteLine("🛠️ Contenido Encriptado en Base64:\n" + Convert.ToBase64String(encryptedContent) + "\n");

        //Probar la desencriptación para verificar
        string decryptedFileContent = DecryptAES(encryptedContent, aesKey, aesIV);
        Console.WriteLine("\n🔓 Contenido Desencriptado del Archivo:\n" + decryptedFileContent);
    }

    //encriptar con AES
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

    //simulacion equisd  desencriptar con AES
    static string DecryptAES(byte[] cipherText, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using MemoryStream ms = new(cipherText);
        using CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using StreamReader sr = new(cs);

        return sr.ReadToEnd();
    }
}
