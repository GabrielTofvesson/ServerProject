using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tofvesson.Crypto
{
    /// <summary>
    /// Secure Hashing Alorithm implementations
    /// </summary>
    public static class SHA
    {
        public static byte[] SHA1(byte[] message)
        {
            // Initialize buffers
            uint h0 = 0x67452301;
            uint h1 = 0xEFCDAB89;
            uint h2 = 0x98BADCFE;
            uint h3 = 0x10325476;
            uint h4 = 0xC3D2E1F0;

            // Pad message
            int ml = message.Length + 1;
            byte[] msg = new byte[ml + ((960 - (ml*8 % 512)) % 512)/8 + 8];
            Array.Copy(message, msg, message.Length);
            msg[message.Length] = 0x80;
            long len = message.Length * 8;
            for (int i = 0; i < 8; ++i) msg[msg.Length - 1 - i] = (byte)((len >> (i*8)) & 255);
            //Support.WriteToArray(msg, message.Length * 8, msg.Length - 8);
            //for (int i = 0; i <4; ++i) msg[msg.Length - 5 - i] = (byte)(((message.Length*8) >> (i * 8)) & 255);

            int chunks = msg.Length / 64;

            // Perform hashing for each 512-bit block
            for(int i = 0; i<chunks; ++i)
            {

                // Split block into words
                uint[] w = new uint[80];
                for(int j = 0; j<16; ++j)
                    w[j] |= (uint) ((msg[i * 64 + j * 4] << 24) | (msg[i * 64 + j * 4 + 1] << 16) | (msg[i * 64 + j * 4 + 2] << 8) | (msg[i * 64 + j * 4 + 3] << 0));

                // Expand words
                for(int j = 16; j<80; ++j)
                    w[j] = Rot(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);

                // Initialize chunk-hash
                uint
                    a = h0,
                    b = h1,
                    c = h2,
                    d = h3,
                    e = h4;

                // Do hash rounds
                for (int t = 0; t<80; ++t)
                {
                    uint tmp = Rot(a, 5) + func(t, b, c, d) + e + K(t) + w[t];
                    e = d;
                    d = c;
                    c = Rot(b, 30);
                    b = a;
                    a = tmp;
                }
                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
            }

            return Support.WriteContiguous(new byte[20], 0, Support.SwapEndian(h0), Support.SwapEndian(h1), Support.SwapEndian(h2), Support.SwapEndian(h3), Support.SwapEndian(h4));
        }

        private static uint func(int t, uint b, uint c, uint d) =>
            t < 20 ? (b & c) | ((~b) & d) :
            t < 40 ? b ^ c ^ d :
            t < 60 ? (b & c) | (b & d) | (c & d) :
            /*t<80*/ b ^ c ^ d;

        private static uint K(int t) =>
            t < 20 ? 0x5A827999 :
            t < 40 ? 0x6ED9EBA1 :
            t < 60 ? 0x8F1BBCDC :
            /*t<80*/ 0xCA62C1D6 ;

        private static uint Rot(uint val, int by) => (val << by) | (val >> (32 - by));
    }
}
