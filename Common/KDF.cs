using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tofvesson.Crypto
{
    // Class for key derivation
    public static class KDF
    {
        public delegate byte[] HashFunction(byte[] message);
        public static byte[] HMAC(byte[] key, byte[] message, HashFunction func, int blockSizeBytes)
        {
            if (key.Length > blockSizeBytes) key = func(key);
            else if (key.Length < blockSizeBytes)
            {
                byte[] b = new byte[blockSizeBytes];
                Array.Copy(key, b, key.Length);
                key = b;
            }

            byte[] o_key_pad = new byte[blockSizeBytes];
            byte[] i_key_pad = new byte[blockSizeBytes];
            for (int i = 0; i < blockSizeBytes; ++i)
            {
                o_key_pad[i] = (byte)(key[i] ^ 0x5c);
                i_key_pad[i] = (byte)(key[i] ^ 0x36);
            }
            return func(Support.Concatenate(o_key_pad, func(Support.Concatenate(i_key_pad, message))));
        }

        public static byte[] HMAC_SHA1(byte[] key, byte[] message) => HMAC(key, message, SHA.SHA1, 64);

        public delegate byte[] PRF(byte[] key, byte[] salt);
        public static byte[] PBKDF2(PRF function, byte[] password, byte[] salt, int iterations, int dklen)
        {
            byte[] dk = new byte[0];
            uint iter = 1;
            while (dk.Length < dklen)
            {
                // F-function
                byte[] u = function(password, Support.Concatenate(salt, Support.WriteToArray(new byte[4], Support.SwapEndian(iter), 0)));
                byte[] ures = new byte[u.Length];
                Array.Copy(u, ures, u.Length);
                for(int i = 1; i<iterations; ++i)
                {
                    u = function(password, u);
                    for (int j = 0; j < u.Length; ++j) ures[j] ^= u[j];
                }

                dk = Support.Concatenate(dk, ures);

                ++iter;
            }

            return dk.ToLength(dklen);
        }
    }
}
