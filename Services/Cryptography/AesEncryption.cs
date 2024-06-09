using System.Security.Cryptography;

namespace Save_cloud.Services.Cryptography
{
    public class AesEncryption
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public AesEncryption(byte[] key, byte[] iv)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _iv = iv ?? throw new ArgumentNullException(nameof(iv));
        }

        public void EncryptFile(string inputFilePath, string outputFilePath)
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = _key;
                aes.IV = _iv;

                // Создаем поток для чтения из исходного файла и поток для записи в зашифрованный файл
                using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                {
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    // Создаем CryptoStream для шифрования данных
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // Шифруем данные из исходного файла и записываем их в зашифрованный файл
                        inputFileStream.CopyTo(cryptoStream);
                    }
                }
            }
        }

        public void DecryptFile(string inputFilePath, string outputFilePath)
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = _key;
                aes.IV = _iv;

                // Создаем поток для чтения из зашифрованного файла и поток для записи в расшифрованный файл
                using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                {
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // Создаем CryptoStream для расшифровки данных
                    using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    {
                        // Расшифровываем данные из зашифрованного файла и записываем их в расшифрованный файл
                        cryptoStream.CopyTo(outputFileStream);
                    }
                }
            }
        }
    }
}
