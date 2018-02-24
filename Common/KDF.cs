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

        // Hash-based Message Authentication Codes: generates a code for verifying the sender of a message and the like
        public static byte[] HMAC(byte[] key, byte[] message, HashFunction func, int blockSizeBytes)
        {
            if (key.Length > blockSizeBytes) key = func(key);
            else if (key.Length < blockSizeBytes)
            {
                byte[] b = new byte[blockSizeBytes];
                Array.Copy(key, b, key.Length);
                key = b;
            }

            byte[] o_key_pad = new byte[blockSizeBytes]; // Outer padding
            byte[] i_key_pad = new byte[blockSizeBytes]; // Inner padding
            for (int i = 0; i < blockSizeBytes; ++i)
            {
                // Combine padding with key
                o_key_pad[i] = (byte)(key[i] ^ 0x5c);
                i_key_pad[i] = (byte)(key[i] ^ 0x36);
            }
            return func(Support.Concatenate(o_key_pad, func(Support.Concatenate(i_key_pad, message))));
        }

        // Perform HMAC using SHA1
        public static byte[] HMAC_SHA1(byte[] key, byte[] message) => HMAC(key, message, SHA.SHA1, 20);

        // Pseudorandom function delegate
        public delegate byte[] PRF(byte[] key, byte[] salt);

        // Password-Based Key Derivation Function 2. Used to generate "pseudorandom" keys from a given password and salt using a certain PRF applied a certain amount of times (iterations).
        // dklen specified the "derived key length" in bytes. It is recommended to use a high number for the iterations variable (somewhere around 4096 is the standard for SHA1 currently)
        public static byte[] PBKDF2(PRF function, byte[] password, byte[] salt, int iterations, int dklen)
        {
            byte[] dk = new byte[0]; // Create a placeholder for the derived key
            uint iter = 1; // Track the iterations
            while (dk.Length < dklen)
            {
                // F-function
                // The F-function (PRF) takes the amount of iterations performed in the opposite endianness format from what C# uses, so we have to swap the endianness
                byte[] u = function(password, Support.Concatenate(salt, Support.WriteToArray(new byte[4], Support.SwapEndian(iter), 0)));
                byte[] ures = new byte[u.Length];
                Array.Copy(u, ures, u.Length);
                for(int i = 1; i<iterations; ++i)
                {
                    // Iteratively apply the PRF
                    u = function(password, u);
                    for (int j = 0; j < u.Length; ++j) ures[j] ^= u[j];
                }

                // Concatenate the result to the dk
                dk = Support.Concatenate(dk, ures);

                ++iter;
            }

            // Clip aby bytes past what we needed (yes, that's really what the standard is)
            return dk.ToLength(dklen);
        }
    }
}
