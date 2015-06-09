using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Cryptopals
{
    public partial class Crypto
    {
        public static byte[] Pkcs7Padding(byte[] input, int blockSize)
        {
            var paddingSize = blockSize - input.Length;
            var output = new byte[blockSize];
            Buffer.BlockCopy(input, 0, output, 0, input.Length);

            for (var i = input.Length; i < blockSize; i++)
            {
                output[i] = (byte)paddingSize;
            }
            return output;
        }

        public static byte[] EcbAesEncrypt(byte[] message, byte[] key, byte[] iv)
        {
            var aes = new AesManaged
            {
                KeySize = 128,
                Key = key,
                Mode = CipherMode.ECB,
                IV = iv,
                Padding = PaddingMode.None
            };

            var ict = aes.CreateEncryptor(aes.Key, aes.IV);
            return ict.TransformFinalBlock(message, 0, message.Length);
        }

        public static byte[] CbcAesEncrypt(byte[] message, byte[] key, byte[] iv)
        {
            var b = new List<byte>();
            for (var i = 0; i < message.Length / 16; i++)
            {
                var messageBlock = message.Skip(i * 16).Take(16).ToArray();
                var encryptedBlock = EcbAesEncrypt(messageBlock, key, iv);
                b.AddRange(encryptedBlock);
                iv = encryptedBlock;
            }

            return b.ToArray();
        }

        public static byte[] CbcAesDecrypt(byte[] message, byte[] key)
        {
            var iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            var b = new List<byte>();
            for (var i = 0; i < message.Length / 16; i++)
            {
                var cipherText = message.Skip(i * 16).Take(16).ToArray();
                b.AddRange(Xor(iv, EcbAesDecrypt(cipherText, key, iv)));
                iv = cipherText;
            }

            return b.ToArray();
        }

        public static byte[] EncryptionOracle(byte[] message)
        {
            //Generate random key
            var random = new Random();
            var randomAesKey = new byte[16];
            random.NextBytes(randomAesKey);

            //Pad message before & after with random bytes
            var paddedMessage = new List<byte>();
            var randomList = new List<byte>(random.Next(5, 10));
            for (var i = 0; i < randomList.Capacity; i++)
                randomList.Add((byte)random.Next());
            //paddedMessage.AddRange(randomList.ToArray());

            paddedMessage.AddRange(message);

            randomList = new List<byte>(random.Next(5, 10));
            for (var i = 0; i < randomList.Capacity; i++)
                randomList.Add((byte)random.Next());
            //paddedMessage.AddRange(randomList.ToArray());

            var input = paddedMessage.ToArray();
            if (input.Length % 16 != 0)
            {
                input = Pkcs7Padding(input, input.Length + 16 - input.Length % 16);
            }

            //encrypt using either EBC/CBC depending on chance
            //TODO: make IV random
            var iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            //var encryptedMessage = random.Next(0, 2) == 0 ?
            //                   EcbAesEncrypt(input, randomAesKey, iv) :
            //                   CbcAesDecrypt(input, randomAesKey);

            var encryptedMessage = EcbAesDecrypt(input, randomAesKey, iv);
            return encryptedMessage;
        }

        public static string DecipherEcryptionType(byte[] encryptedMessage)
        {

            for (var i = 0; i < encryptedMessage.Length; i++)
            {
                Console.Out.Write("{0} ", encryptedMessage[i]);
            }


            int matchCount = 0, maxMatchCount = 0;
            for (var i = 0; i < encryptedMessage.Length - 16; i++)
            {
                if (encryptedMessage[i] == encryptedMessage[i + 16])
                {
                    matchCount++;
                    maxMatchCount = Math.Max(maxMatchCount, matchCount);
                }
                else
                {
                    maxMatchCount = Math.Max(maxMatchCount, matchCount);
                    matchCount = 0;
                }
            }


            return maxMatchCount == 16 ? "ECB" : "CBC";
        }


        public static void Main(string[] args)
        {
            //var aesCbcDecryptedText = Encoding.UTF8.GetString(
            //                CbcAesDecrypt(
            //                    Convert.FromBase64String(File.ReadAllText(@"Data\10.txt")),
            //                    Encoding.UTF8.GetBytes("YELLOW SUBMARINE")));
            //Console.WriteLine("Q10: {0}", aesCbcDecryptedText);

            //var s =
            //    Encoding.UTF8.GetString(Convert.FromBase64String(
            //        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));

            //var encryptedMessage = EncryptionOracle(Convert.FromBase64String(File.ReadAllText(@"Data\7.txt")));

            var encryptedMessage = EncryptionOracle(Encoding.UTF8.GetBytes("YELLOW SUBMARINYELLOW SUBMARIN"));
            DecipherEcryptionType(encryptedMessage);
            Console.WriteLine("Q11: {0}", Encoding.UTF8.GetString(encryptedMessage));
            Console.ReadKey();

        }
    }
}
