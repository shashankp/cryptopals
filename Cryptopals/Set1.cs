using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Cryptopals
{
    public partial class Crypto
    {
        public static string HexToBase64(string hex)
        {
            var bytes = HexToBytes(hex);
            return Convert.ToBase64String(bytes);
        }

        public static string Base64ToHex(string base64)
        {
            var sb = new StringBuilder();
            foreach (var b in Convert.FromBase64String(base64))
            {
                sb.Append(b.ToString("X2"));
            }
            return sb.ToString();
        }

        public static string HexToString(string hex)
        {
            var bytes = HexToBytes(hex);
            return Encoding.UTF8.GetString(bytes);
        }

        public static string StringToHex(string s)
        {
            var sb = new StringBuilder();
            foreach (var c in s)
            {
                sb.Append(((byte)c).ToString("X2"));
            }
            return sb.ToString();
        }

        public static string BytesToHex(byte[] b)
        {
            var sb = new StringBuilder();
            foreach (var c in b)
            {
                sb.Append(c.ToString("X2"));
            }
            return sb.ToString();
        }

        public static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 != 0) throw new InvalidDataException("Input should be of even length.");

            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static byte[] Xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) throw new InvalidDataException("Inputs should be of equal length");

            var xor = new byte[a.Length];
            for (var i = 0; i < a.Length; i++)
            {
                xor[i] = (byte)(a[i] ^ b[i]);
            }

            return xor;
        }

        public static int HammingDistance(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) throw new InvalidDataException("Input strings length should be equal");

            var hammingDistance = 0;
            for (var i = 0; i < a.Length; i++)
            {
                var c = (byte)(a[i] ^ b[i]);
                while (c != 0)
                {
                    if (c % 2 == 1) hammingDistance++;
                    c >>= 1;
                }
            }

            return hammingDistance;
        }

        public static long Score(string plainText)
        {
            //var vowelScore = plainText.Count(c => "aeiou".IndexOf(c) != -1);
            var validChars =
                plainText.Where(c => (
                    c == ' ' || c == ',' ||
                    c == '\n' || c == '\'' ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z'))).LongCount();
            return validChars;
        }

        public static string GenerateRepeatingKey(string hexKey, long targetLength)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < targetLength; i++)
            {
                sb.Append(hexKey[i % hexKey.Length]);
            }
            return sb.ToString();
        }

        public static string XorEncrypt(string plainTextMessage, string plainTextKey)
        {
            var hexMessage = StringToHex(plainTextMessage);
            var encryptionKey = GenerateRepeatingKey(StringToHex(plainTextKey), hexMessage.Length);
            return BytesToHex(Xor(HexToBytes(encryptionKey), HexToBytes(hexMessage)));
        }

        public static string XorDecrypt(byte[] b)
        {
            var hex = BytesToHex(b);
            var dict = new SortedDictionary<long, List<string>>();
            var hexKey = String.Empty;
            var j = 0;

            while (hexKey != "FF")
            {
                hexKey = (++j).ToString("X2");
                var tryMe = GenerateRepeatingKey(hexKey, hex.Length);
                var output = Xor(HexToBytes(hex), HexToBytes(tryMe));
                var stringOutput = Encoding.UTF8.GetString(output);
                var score = Score(stringOutput);

                if (dict.ContainsKey(score))
                    dict[score].Add(stringOutput);
                else
                    dict.Add(score, new List<string> { stringOutput });
            }

            return dict.First(kv => kv.Key == dict.Keys.Max()).Value[0];
        }

        public static string DecipherKey(string base64XorEncrypted)
        {
            var bytes = Convert.FromBase64String(base64XorEncrypted);
            var hex = Base64ToHex(base64XorEncrypted);

            var scores = new Dictionary<int, double>();
            for (var tryLength = 2; tryLength <= 40; tryLength++)
            {
                var firstBlock = bytes.Take(tryLength).ToArray();
                var secondBlock = bytes.Skip(tryLength).Take(tryLength).ToArray();
                var thirdBlock = bytes.Skip(2 * tryLength).Take(tryLength).ToArray();
                var fourthBlock = bytes.Skip(3 * tryLength).Take(tryLength).ToArray();
                var fifthBlock = bytes.Skip(4 * tryLength).Take(tryLength).ToArray();
                var score = (double)HammingDistance(firstBlock, secondBlock) / tryLength +
                        (double)HammingDistance(firstBlock, thirdBlock) / tryLength +
                        (double)HammingDistance(firstBlock, fourthBlock) / tryLength +
                        (double)HammingDistance(firstBlock, fifthBlock) / tryLength;
                scores.Add(tryLength, score);
            }

            //Try keySizes
            var bestMatchKeyString = String.Empty;
            long bestScore = 0;
            foreach (var item in scores.ToList().OrderBy(pair => pair.Value).Take(3))
            {
                var keySize = item.Key;
                long totalScore = 0;
                var keyString = String.Empty;

                //transpose blocks
                for (var i = 0; i < keySize; i++)
                {
                    var decodeMe = new List<byte>();
                    for (var j = 0; j < bytes.Count() / keySize; j++)
                    {
                        decodeMe.Add(bytes[i + j * keySize]);
                    }
                    var decoded = XorDecrypt(decodeMe.ToArray());
                    keyString += (char)(decoded[0] ^ decodeMe[0]);
                    totalScore += Score(XorDecrypt(decodeMe.ToArray()));
                }

                if (totalScore <= bestScore) continue;
                bestScore = totalScore;
                bestMatchKeyString = keyString;
            }

            var key = GenerateRepeatingKey(StringToHex(bestMatchKeyString), hex.Length);
            return Encoding.UTF8.GetString(Xor(HexToBytes(hex), HexToBytes(key)));
        }

        public static byte[] EcbAesDecrypt(byte[] encryptedMessage, byte[] key, byte[] iv)
        {
            var aes = new AesManaged
            {
                KeySize = 128,
                Key = key,
                Mode = CipherMode.ECB,
                IV = iv,
                Padding = PaddingMode.None
            };

            var ict = aes.CreateDecryptor();
            return ict.TransformFinalBlock(encryptedMessage, 0, encryptedMessage.Length);
        }

        public static string TryFindEcbEncryptedString(IEnumerable<string> base64EncodedString)
        {
            var repetitions = new Dictionary<string, int>();
            foreach (var base64Encoded in base64EncodedString)
            {
                var h = Base64ToHex(base64Encoded);
                var d = new Dictionary<string, int>();

                //Check for repetition of 16bytes
                for (var i = 0; i < h.Length / 32; i++)
                {
                    //32 hex digits make 16bytes
                    var bytes16 = h.Substring(i * 32, 32);
                    if (d.ContainsKey(bytes16))
                        d[bytes16]++;
                    else d.Add(h.Substring(i * 32, 32), 1);
                }
                repetitions.Add(base64Encoded, d.Keys.Count);
            }

            return repetitions.First(kv => kv.Value == repetitions.Values.Min()).Key;
        }

        public static void Set1()
        {
            //Q1:
            const string hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            const string base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
            Debug.Assert(base64.Equals(HexToBase64(hex), StringComparison.OrdinalIgnoreCase), "HexToBase64 failed");
            Debug.Assert(hex.Equals(Base64ToHex(HexToBase64(hex)), StringComparison.OrdinalIgnoreCase), "Base64ToHex failed");

            //Q2:
            Debug.Assert(BytesToHex(Xor(HexToBytes("1c0111001f010100061a024b53535009181c"),
                           HexToBytes("686974207468652062756c6c277320657965")))
                .Equals("746865206b696420646f6e277420706c6179", StringComparison.OrdinalIgnoreCase), "Xor failed");

            //Q3:
            //key:58 
            //decrypted: Cooking MC'a like a pound of bacon
            const string crypticMessage1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            var decryptedMessage1 = XorDecrypt(HexToBytes(crypticMessage1));
            Console.WriteLine("Q3: {0}", decryptedMessage1);

            //Q4:
            //key:35
            //encrypted: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
            //decrypted: Now that the party is jumping
            var decryptedMessages = new Dictionary<string, long>();
            File.ReadAllLines(@"Data\4.txt")
                .ToList()
                .ForEach(item =>
                {
                    var d = XorDecrypt(HexToBytes(item));
                    decryptedMessages.Add(d, Score(d));
                });
            var decryptedMessage2 = decryptedMessages.First(kv => kv.Value == decryptedMessages.Values.Max()).Key;
            Console.WriteLine("Q4: {0}", decryptedMessage2);

            //Q5:
            const string key = "ICE";
            const string message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            const string encryptedMessageRef = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
            var encryptedMessage = XorEncrypt(message, key);
            Debug.Assert(encryptedMessage.Equals(encryptedMessageRef, StringComparison.OrdinalIgnoreCase), "Encryption failed");

            //Q6: 
            //key: "Terminator X: Bring the noise"
            //decrypted: I'm back and I'm ringin' the bell...
            var xorEncrypted = File.ReadAllText(@"Data\6.txt");
            var decryptedXor = DecipherKey(xorEncrypted);
            File.WriteAllText(@"Data\7-out.txt", decryptedXor);
            Console.WriteLine("Q6: {0}", decryptedXor);

            //Q7:
            //decrypted: I'm back and I'm ringin' the bell...
            var base64Encoded = File.ReadAllText(@"Data\7.txt");
            const string aesKey = "YELLOW SUBMARINE";
            var decryptedEcb = EcbAesDecrypt(Convert.FromBase64String(base64Encoded),
                                                Encoding.UTF8.GetBytes(aesKey),
                                                new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
            Console.WriteLine("Q7: {0}", decryptedEcb);

            //Q8:
            //found: d880619740a8a19b784...
            var ecbEncryptedString = TryFindEcbEncryptedString(File.ReadAllLines(@"Data\8.txt"));
            Console.WriteLine("Q8: {0}", ecbEncryptedString);

            Console.ReadKey();
        }
    }
}
