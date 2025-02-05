using System;
using System.IO;
using System.Security.Cryptography;

class AESKeyGen
{
    static void Main(string[] args)
    {
        string aesKeyFilePath = "aes_key.txt"; // Archivo para guardar la clave AES

        // Generar clave AES y IV
        (byte[] aesKey, byte[] aesIV) = GenerateAESKey();
        Console.WriteLine("🔑 Clave Privada (AES):\n" + Convert.ToBase64String(aesKey) + "\n");
        Console.WriteLine("IV Generado: " + Convert.ToBase64String(aesIV) + "\n");

        // Guardar la clave AES en un archivo
        try
        {
            File.WriteAllText(aesKeyFilePath, Convert.ToBase64String(aesKey));
            Console.WriteLine($"✅ Clave AES guardada en '{aesKeyFilePath}'.\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error al guardar la clave AES: {ex.Message}");
        }
    }

    // Método para generar clave AES y IV
    static (byte[] Key, byte[] IV) GenerateAESKey()
    {
        using Aes aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();
        return (aes.Key, aes.IV);
    }
}
