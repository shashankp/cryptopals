using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptopals
{
    [TestClass]
    public class TestSet2
    {
        [TestMethod]
        public void TestPkcs7Padding()
        {
            Assert.AreEqual(
                 Encoding.ASCII.GetString(Crypto.Pkcs7Padding(Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), 20)),
                 "YELLOW SUBMARINE\x04\x04\x04\x04");
        }

        [TestMethod]
        public void TestEcbAesEncrypt()
        {
            var key = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            var message = Encoding.ASCII.GetBytes("BEATLES");
            var iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            var hexResult = "6EB455C2F06B251A7650138DD9A8C9ED";

            if (message.Length % 16 != 0)
            {
                message = Crypto.Pkcs7Padding(message, message.Length + 16 - message.Length % 16);
            }

            Assert.IsTrue(hexResult.Equals(Crypto.BytesToHex(Crypto.EcbAesEncrypt(message, key, iv))));
        }

        [TestMethod]
        public void TestCbcAesEncrypt()
        {
            var key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
            var message = Encoding.UTF8.GetBytes("I'm back and I'm ringin' the bell");
            var iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            var result = "6EB455C2F06B251A7650138DD9A8C9ED";

            if (message.Length % 16 != 0)
            {
                message = Crypto.Pkcs7Padding(message, message.Length + 16 - message.Length % 16);
            }

            Assert.IsTrue(result.Equals(Crypto.BytesToHex(Crypto.CbcAesEncrypt(message, key, iv))));
        }

        [TestMethod]
        public void TestCbcAesDecrypt()
        {
            const string key = "YELLOW SUBMARINE";

            var input = Convert.FromBase64String(File.ReadAllText(@"Data\10.txt"));
            if (input.Length % 16 != 0)
            {
                input = Crypto.Pkcs7Padding(input, input.Length + 16 - input.Length % 16);
            }

            Assert.IsTrue(
                Encoding.UTF8.GetString(
                    Crypto.CbcAesDecrypt(
                        input,
                        Encoding.UTF8.GetBytes(key)))
                .Contains("Play that funky music"));
        }
    }
}
