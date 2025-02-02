using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8; // Permitir caracteres Unicode en la consola
        Console.ForegroundColor = ConsoleColor.Cyan; // Cambia el color del texto
        Console.WriteLine("🔐  SISTEMA DE ENCRIPTACIÓN RSA CON C# PUNTOS EXTRA 🔐\n");

        // Generar las claves RSA
        using RSACryptoServiceProvider rsa = new(2048);
        string publicKey = rsa.ToXmlString(false);
        string privateKey = rsa.ToXmlString(true);

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("🗝️ Clave Pública:\n" + publicKey + "\n");
        Console.WriteLine("🔏 Clave Privada:\n" + privateKey + "\n");

        // Solicitar el mensaje a encriptar
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("Introduce el mensaje a encriptar: ");
        string originalMessage = Console.ReadLine() ?? string.Empty;

        // Encriptar el mensaje
        byte[] encryptedMessage = EncryptRSA(originalMessage, publicKey);
        string encryptedMessageBase64 = Convert.ToBase64String(encryptedMessage);

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n🔒 Mensaje Encriptado (Base64): " + encryptedMessageBase64);

        // Desencriptar el mensaje
        string decryptedMessage = DecryptRSA(encryptedMessage, privateKey);
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("\n🔓 Mensaje Desencriptado: " + decryptedMessage);

        Console.ResetColor(); 
    }

    // Encriptar con RSA
    static byte[] EncryptRSA(string message, string publicKey)
    {
        using RSACryptoServiceProvider rsa = new(2048);
        rsa.FromXmlString(publicKey);
        byte[] data = Encoding.UTF8.GetBytes(message);
        return rsa.Encrypt(data, false);
    }

    // Desencriptar con RSA
    static string DecryptRSA(byte[] encryptedMessage, string privateKey)
    {
        using RSACryptoServiceProvider rsa = new(2048);
        rsa.FromXmlString(privateKey);
        byte[] decryptedData = rsa.Decrypt(encryptedMessage, false);
        return Encoding.UTF8.GetString(decryptedData);
    }
}
