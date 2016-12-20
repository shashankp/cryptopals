using System;
using System.IO;
using System.Text;
using NUnit.Framework;

namespace Cryptopals
{
    [TestFixture]
    public class TestSet1
    {
        private string _hex, _base64, _ascii;

		[SetUp]
        public void Initialize()
        {
            _hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            _base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
            _ascii = "I'm killing your brain like a poisonous mushroom";
        }

        [Test]
        public void TestHexToBase64()
        {
            Assert.IsTrue(Crypto.HexToBase64(_hex).Equals(_base64, StringComparison.OrdinalIgnoreCase));
        }

        [Test]
        public void TestBase64ToHex()
        {
            Assert.IsTrue(Crypto.Base64ToHex(_base64).Equals(_hex, StringComparison.OrdinalIgnoreCase));
            Assert.IsTrue(Crypto.Base64ToHex(Crypto.HexToBase64(_hex)).Equals(_hex, StringComparison.OrdinalIgnoreCase));
        }

        [Test]
        public void TestHexToString()
        {
            Assert.IsTrue(Crypto.HexToString(_hex).Equals(_ascii, StringComparison.OrdinalIgnoreCase));
        }

        [Test]
        public void TestHexToBytes_takes_even_length_input_only()
        {
			Assert.Throws<InvalidDataException>(() => Crypto.HexToBytes("123") );
        }

        [Test]
        public void TestXor()
        {
            Assert.IsTrue(
                 Crypto.BytesToHex(Crypto.Xor(Crypto.HexToBytes("1c0111001f010100061a024b53535009181c"),
                           Crypto.HexToBytes("686974207468652062756c6c277320657965")))
                .Equals("746865206b696420646f6e277420706c6179", StringComparison.OrdinalIgnoreCase));

            Assert.IsTrue(
				Encoding.UTF8.GetString(Crypto.Xor(Crypto.HexToBytes("1c0111001f010100061a024b53535009181c"),
                                               Crypto.HexToBytes("686974207468652062756c6c277320657965")))
                     .Equals("the kid don't play", StringComparison.OrdinalIgnoreCase));
        }

        [Test]
        public void TestXor_Unequal_inputs()
        {
			Assert.Throws<InvalidDataException>(() => Crypto.Xor(Crypto.HexToBytes("abcd"), Crypto.HexToBytes("abcdef")));
        }

        [Test]
        public void TestRepeatingKey()
        {
            Assert.AreEqual(Crypto.GenerateRepeatingKey("01", 5), "01010");
            Assert.AreEqual(Crypto.GenerateRepeatingKey("01", 6), "010101");
            Assert.AreEqual(Crypto.GenerateRepeatingKey("012", 6), "012012");
        }

        [Test]
        public void TestEncrypt()
        {
            const string key = "ICE";
            const string message = "Burning 'em, if you ain't quick and nimble\n" +
                                   "I go crazy when I hear a cymbal";
            const string encryptedMessage = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

            Assert.AreEqual(Crypto.XorEncrypt(message, key).Length, encryptedMessage.Length);
            Assert.IsTrue(Crypto.XorEncrypt(message, key).Equals(encryptedMessage, StringComparison.OrdinalIgnoreCase));
        }

        [Test]
        public void TestStringToHex()
        {
            Assert.IsTrue(Crypto.StringToHex("the kid don't play").Equals("746865206b696420646f6e277420706c6179", StringComparison.OrdinalIgnoreCase));
        }

        [Test]
        public void TestHammingDistance()
        {
            Assert.AreEqual(Crypto.HammingDistance(Encoding.UTF8.GetBytes("this is a test"), Encoding.UTF8.GetBytes("wokka wokka!!!")), 37);
        }

        [Test]
        public void TestHammingDistance_takes_equal_length_inputs_only()
        {
			Assert.Throws<InvalidDataException>(() => Crypto.HammingDistance(Encoding.UTF8.GetBytes("abc"), Encoding.UTF8.GetBytes("abcd")));
        }

        [Test]
        public void TestEcbAesDecrypt()
        {
            Assert.IsTrue(Encoding.UTF8.GetString(Crypto.EcbAesDecrypt(
                                    Convert.FromBase64String(File.ReadAllText(@"Data\7.txt")),
                                    Encoding.UTF8.GetBytes("YELLOW SUBMARINE"),
                                    new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }))
			              .StartsWith("I'm back and I'm ringin' the bell", StringComparison.Ordinal));
        }

        [Test]
        public void TestTryFindEcbEncryptedString()
        {
            Assert.AreEqual(Crypto.TryFindEcbEncryptedString(new[] { 
                "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
                "8a10247f90d0a05538888ad6205882196f5f6d05c21ec8dca0cb0be02c3f8b09e382963f443aa514daa501257b09a36bf8c4c392d8ca1bf4395f0d5f2542148c7e5ff22237969874bf66cb85357ef99956accf13ba1af36ca7a91a50533c4d89b7353f908c5a166774293b0bf6247391df69c87dacc4125a99ec417221b58170e633381e3847c6b1c28dda2913c011e13fc4406f8fe73bbf78e803e1d995ce4d"
                }),
                "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");
        }

        [Test]
        public void TestScore()
        {
            Assert.AreEqual(Crypto.Score("Hi, ^$"), 4);
        }
    }
}
