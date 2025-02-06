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

    // Method to encrypt a file using AES in CBC mode
    public static byte[] EncryptFileWithAes(string filePath, byte[] aesKey, out byte[] iv)
    {
        const int blockSize = 16;
        using (Aes aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.Mode = CipherMode.ECB; // Usar modo ECB
            aes.Padding = PaddingMode.None; // Sin padding, lo manejaremos manualmente
    
            iv = new byte[blockSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv); // Generar un IV aleatorio
            }
    
            try
            {
                using (FileStream inputFileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (MemoryStream outputMemoryStream = new MemoryStream())
                {
                    
                    outputMemoryStream.Write(iv, 0, iv.Length);
    
                    byte[] buffer = new byte[blockSize];
                    byte[] prevBlock = iv;
                    int bytesRead;
    
                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        while ((bytesRead = inputFileStream.Read(buffer, 0, blockSize)) > 0)
                        {
                            
                            if (bytesRead < blockSize)
                            {
                                int padLen = blockSize - bytesRead;
                                for (int i = bytesRead; i < blockSize; i++)
                                {
                                    buffer[i] = (byte)padLen;
                                }
                            }
    
                            // Operación CBC: XOR con el bloque anterior (o IV para el primero)
                            for (int i = 0; i < blockSize; i++)
                            {
                                buffer[i] ^= prevBlock[i];
                            }
    
                            // Encriptar el bloque
                            byte[] encryptedBlock = new byte[blockSize];
                            encryptor.TransformBlock(buffer, 0, blockSize, encryptedBlock, 0);
    
                            // Guardar el bloque encriptado como el nuevo "prevBlock" y escribir al output
                            prevBlock = encryptedBlock;
                            outputMemoryStream.Write(encryptedBlock, 0, encryptedBlock.Length);
                        }
                    }
                    Console.WriteLine(BitConverter.ToString(outputMemoryStream.ToArray()));
                    Console.WriteLine(BitConverter.ToString(iv));
                    return outputMemoryStream.ToArray();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during encryption: {ex.Message}");
                throw;
            }
        }
    }

    // Method to encrypt the AES key using RSA
    public static byte[] EncryptAesKeyWithRsa(byte[] aesKey, RSA rsa)
    {
        return rsa.Encrypt(aesKey, RSAEncryptionPadding.Pkcs1);
    }

    // Method to load an RSA public key from a .pem file
    public static RSA LoadPublicKeyFromPem(string pemFilePath)
    {
        string pemContent = File.ReadAllText(pemFilePath);
        pemContent = pemContent
            .Replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .Replace("-----END RSA PUBLIC KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();
    
        byte[] publicKeyBytes = Convert.FromBase64String(pemContent);
        RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKeyBytes, out _);
        return rsa;
    }

    // Method to load an RSA private key from a .pem file
    public static RSA LoadPrivateKeyFromPem(string pemFilePath)
    {
        string pemContent = File.ReadAllText(pemFilePath);
        byte[] privateKeyBytes = Convert.FromBase64String(pemContent
            .Replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .Replace("-----END RSA PRIVATE KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", ""));
        RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
        return rsa;
    }

    // Method to generate RSA keys and save them to .pem files
    public static void GenerateRsaKeys(string publicKeyPath, string privateKeyPath)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.KeySize = 2048;

            // Export the public key
            string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
            File.WriteAllText(publicKeyPath, "-----BEGIN RSA PUBLIC KEY-----\n" + publicKey + "\n-----END RSA PUBLIC KEY-----");

            // Export the private key
            string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            File.WriteAllText(privateKeyPath, "-----BEGIN RSA PRIVATE KEY-----\n" + privateKey + "\n-----END RSA PRIVATE KEY-----");
        }
    }

    // Method to decrypt a file using AES and RSA
// Method to decrypt a file using AES and RSA
public static byte[] DecryptFile(
    string encryptedFilePath, 
    string rsaPrivateKeyPath, 
    string encryptedAesKeyPath)
{
    const int blockSize = 16;

    // Read the encrypted AES key from file and decrypt using the RSA private key
    byte[] encryptedAesKey = File.ReadAllBytes(encryptedAesKeyPath);
    RSA rsa = LoadPrivateKeyFromPem(rsaPrivateKeyPath);
    byte[] aesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);

    // Read the full encrypted file (IV + ciphertext)
    byte[] fileData = File.ReadAllBytes(encryptedFilePath);
    if (fileData.Length < blockSize)
        throw new Exception("Insufficient data in encrypted file.");

    // Extract IV (first 16 bytes) and ciphertext (rest)
    byte[] iv = new byte[blockSize];
    
    Array.Copy(fileData, 0, iv, 0, blockSize);
    Console.WriteLine("IV: " + BitConverter.ToString(iv));
    byte[] ciphertext = new byte[fileData.Length - blockSize];
    Array.Copy(fileData, blockSize, ciphertext, 0, ciphertext.Length);

    using (Aes aes = Aes.Create())
    {
        aes.Key = aesKey;
        aes.Mode = CipherMode.ECB;       // Decrypt each block individually
        aes.Padding = PaddingMode.None;    // No padding: we handle PKCS7 manually

        using (ICryptoTransform decryptor = aes.CreateDecryptor())
        using (MemoryStream plaintextStream = new MemoryStream())
        {
            byte[] prevBlock = iv;
            Console.WriteLine("IV: " + BitConverter.ToString(iv));
            for (int offset = 0; offset < ciphertext.Length; offset += blockSize)
            {
                byte[] currentBlock = new byte[blockSize];
                Array.Copy(ciphertext, offset, currentBlock, 0, blockSize);

                // Decrypt the current block (AES-ECB)
                byte[] decryptedBlock = new byte[blockSize];
                decryptor.TransformBlock(currentBlock, 0, blockSize, decryptedBlock, 0);

                // Reverse CBC: XOR with the previous ciphertext block (or IV for the first block)
                for (int i = 0; i < blockSize; i++)
                {
                    Console.WriteLine($"IV {i}: " + BitConverter.ToString(prevBlock));
                    decryptedBlock[i] ^= prevBlock[i];
                }

                plaintextStream.Write(decryptedBlock, 0, blockSize);
                prevBlock = currentBlock;
            }
            
            // Remove PKCS7 padding
            byte[] plaintext = plaintextStream.ToArray();
            int padLen = plaintext[plaintext.Length - 1];
            if (padLen <= 0 || padLen > blockSize || padLen > plaintext.Length)
                throw new Exception("Invalid padding.");

            for (int i = plaintext.Length - padLen; i < plaintext.Length; i++)
            {
                if (plaintext[i] != padLen)
                    throw new Exception("Invalid padding.");
            }

            byte[] result = new byte[plaintext.Length - padLen];
            Array.Copy(plaintext, result, result.Length);

            // Eliminar los dos primeros bloques de 16 bytes
            int blocksToRemove = 1;
            byte[] finalResult = new byte[result.Length - (blocksToRemove * blockSize)];
            Array.Copy(result, blocksToRemove * blockSize, finalResult, 0, finalResult.Length);

            // Convert the final result to a UTF-8 string
            string resultString = Encoding.UTF8.GetString(finalResult);
            Console.WriteLine("PlainText: " + resultString);

            return finalResult;
    }
}
}

public class Program
{
    public static void Main(string[] args)
    {
        if (args.Length > 1 && args[0] == "encrypt")
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: dotnet run -- encrypt <file-path> <public-key.pem>");
                return;
            }

            // Encrypt the file using AES and encrypt the AES key with RSA
            string filePath = args[1];
            string publicKeyPath = args[2];

            // Generate the AES key
            byte[] aesKey = AesEncryptor.GenerateAesKey();
            Console.WriteLine("Generated AES Key (Base64): " + Convert.ToBase64String(aesKey));

            // Save the AES key to a .bin file
            string aesKeyFilePath = Path.Combine(Directory.GetCurrentDirectory(), "aesKey.bin");
            File.WriteAllBytes(aesKeyFilePath, aesKey);
            Console.WriteLine("AES Key saved to: " + aesKeyFilePath);

            // Encrypt the file with AES in CBC mode
            byte[] iv;
            byte[] encryptedFileData = AesEncryptor.EncryptFileWithAes(filePath, aesKey, out iv);

            // Encrypt the AES key with RSA
            using (RSA rsa = AesEncryptor.LoadPublicKeyFromPem(publicKeyPath))
            {
                byte[] encryptedAesKey = AesEncryptor.EncryptAesKeyWithRsa(aesKey, rsa);


                // Console.WriteLine(Convert.ToBase64String(encryptedFileData));
                // Console.WriteLine(Convert.ToBase64String(iv));
                // Concatenate IV with encrypted file data
                byte[] ivAndEncryptedData = new byte[iv.Length + encryptedFileData.Length];
                Buffer.BlockCopy(iv, 0, ivAndEncryptedData, 0, iv.Length);
                Buffer.BlockCopy(encryptedFileData, 0, ivAndEncryptedData, iv.Length, encryptedFileData.Length);

                

                // Save the concatenated IV and encrypted file data
                string outputFilePath = Path.ChangeExtension(filePath, ".bin");
                Console.WriteLine("Encrypted file path: " + outputFilePath);
                File.WriteAllBytes(outputFilePath, ivAndEncryptedData);

                string encryptedKeyFilePath = Path.Combine(Path.GetDirectoryName(filePath) ?? string.Empty, Path.GetFileNameWithoutExtension(filePath) + "AesKey.bin");
                File.WriteAllBytes(encryptedKeyFilePath, encryptedAesKey);
                Console.WriteLine("File encrypted successfully:");
                Console.WriteLine("  Encrypted File: " + outputFilePath);
                Console.WriteLine("  Encrypted AES Key: " + encryptedKeyFilePath);
            }
        }
        else if (args.Length > 0 && args[0] == "rsa-keys")
        {
            // Generate RSA keys
            string projectDirectory = Directory.GetCurrentDirectory();
            string publicKeyPath = Path.Combine(projectDirectory, "public_key.pem");
            string privateKeyPath = Path.Combine(projectDirectory, "private_key.pem");
            AesEncryptor.GenerateRsaKeys(publicKeyPath, privateKeyPath);
            Console.WriteLine("RSA keys generated successfully:");
            Console.WriteLine("  Public Key: " + publicKeyPath);
            Console.WriteLine("  Private Key: " + privateKeyPath);
        }
        else if (args.Length > 0 && args[0] == "decrypt")
        {
            // Uso: dotnet run -- decrypt <encryptedFilePath> <rsaPrivateKeyPath> <encryptedAesKeyPath>
            if (args.Length < 4)
            {
                Console.WriteLine("Usage: decrypt <encryptedFilePath> <rsaPrivateKeyPath> <encryptedAesKeyPath>");
                return;
            }

            string encryptedFilePath = args[1];
            string rsaPrivateKeyPath = args[2];
            string encryptedAesKeyPath = args[3];

            try
            {
                byte[] decryptedData = AesEncryptor.DecryptFile(encryptedFilePath, rsaPrivateKeyPath, encryptedAesKeyPath);
                // Opcional: guardar el resultado con extensión .decrypted.txt
                string decryptedFilePath = Path.ChangeExtension(encryptedFilePath, ".decrypted.txt");
                File.WriteAllBytes(decryptedFilePath, decryptedData);
                Console.WriteLine("File decrypted successfully: " + decryptedFilePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error during decryption: " + ex.Message);
            }
        }
        }
    }
}
