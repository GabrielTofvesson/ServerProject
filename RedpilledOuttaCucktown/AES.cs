using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Tofvesson.Crypto
{
    public sealed class AES
    {
        public static readonly byte[] DEFAULT_SALT = new byte[] { 3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5 };
        public static readonly Encoding DEFAULT_ENCODING = Encoding.UTF8;
        public static readonly CryptoPadding DEFAULT_PADDING = new PassthroughPadding();
        private const int BUFFER_SIZE = 2048;

        public byte[] Key { get; private set; }
        public byte[] IV { get; private set; }

        public AES() {
            using (RijndaelManaged r = new RijndaelManaged()) {
                r.GenerateKey();
                r.GenerateIV();
                Key = r.Key;
                IV = r.IV;
            }
            if (Key.Length == 0 || IV.Length == 0) throw new SystemException("Invalid parameter length!");
        }

        public AES(byte[] seed, byte[] salt)
        {
            var keyGenerator = new Rfc2898DeriveBytes(seed, salt, 300);
            using (RijndaelManaged r = new RijndaelManaged())
            {
                r.GenerateIV();
                Key = keyGenerator.GetBytes(32);
                IV = r.IV;
            }
            if (Key.Length == 0 || IV.Length == 0) throw new SystemException("Invalid parameter length!");
        }
        public static AES Load(byte[] key, byte[] iv) => new AES(key, iv, false);
        public AES(byte[] seed) : this(seed, DEFAULT_SALT) { }
        public AES(string password, Encoding e) : this(e.GetBytes(password)) { }
        public AES(string password) : this(DEFAULT_ENCODING.GetBytes(password), DEFAULT_SALT) { }
        private AES(byte[] k, byte[] i, bool b)
        {
            Key = k;
            IV = i;
            if (Key.Length == 0 || IV.Length == 0) throw new SystemException("Invalid parameter length!");
        }


        public byte[] Encrypt(string message) => Encrypt(message, DEFAULT_ENCODING, DEFAULT_PADDING);
        public byte[] Encrypt(string message, Encoding e, CryptoPadding padding) => Encrypt(e.GetBytes(message), padding);
        public byte[] Encrypt(byte[] data, CryptoPadding padding)
        {
            data = padding.Pad(data);
            if (data.Length == 0) throw new SystemException("Invalid message length");
            byte[] result;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV), CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(DEFAULT_ENCODING.GetChars(data));
                        }
                        result = msEncrypt.ToArray();
                    }
                }
            }
            return result;
        }

        public string DecryptString(byte[] data) => DecryptString(data, DEFAULT_ENCODING, DEFAULT_PADDING);
        public string DecryptString(byte[] data, Encoding e, CryptoPadding padding) => new string(e.GetChars(Decrypt(data, padding)));
        public byte[] Decrypt(byte[] data, CryptoPadding padding)
        {
            if (data.Length == 0) throw new SystemException("Invalid message length");
            List<byte> read = new List<byte>();
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, rijAlg.CreateDecryptor(Key, IV), CryptoStreamMode.Read))
                    {
                        byte[] buf = new byte[BUFFER_SIZE];
                        int test;
                        int count;
                        do
                        {
                            count = csDecrypt.Read(buf, 0, buf.Length);
                            if (count == 0)
                            {
                                if ((test = csDecrypt.ReadByte()) == -1) break;
                                read.Add((byte)test);
                            }
                            else for (int i = 0; i < count; ++i) read.Add(buf[i]);
                        } while (true);
                    }
                }
            }
            return padding.Unpad(read.ToArray());
        }

        public void Save(string baseName, bool force = false)
        {
            if (force || !File.Exists(baseName + ".key")) File.WriteAllBytes(baseName + ".key", Key);
            if (force || !File.Exists(baseName + ".iv")) File.WriteAllBytes(baseName + ".iv", IV);
        }

        public byte[] Serialize() => Support.SerializeBytes(new byte[][] { Key, IV });
        public static AES Deserialize(byte[] message, out int read)
        {
            byte[][] output = Support.DeserializeBytes(message, 2);
            read = output[0].Length + output[1].Length + 8;
            return new AES(output[0], output[1], false);
        }

        public static AES Load(string baseName)
        {
            if (!File.Exists(baseName + ".iv") || !File.Exists(baseName + ".key")) throw new SystemException("Required files could not be located");
            return new AES(File.ReadAllBytes(baseName + ".key"), File.ReadAllBytes(baseName + ".iv"), false);
        }
    }


    public static class AESFunctions
    {
        // Substitution box generated for all 256 possible input bytes from a part of a state
        // Generated by getting the multiplicative inverse over GF(2^8) (i.e. the "prime polynomial" x^8 + x^4 + x^3 + x + 1) and applying the affine transformation
        // Used to increase diffusion during encryption, but affine is also used to increase confusion by preventing mathematically aimed attacks
        private static readonly byte[] rijndael_sbox = new byte[]
            {
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
             };

        // MixColumns matrix basis. Used for multiplication over GF(2^8) i.e. mod P(x) where P(x) = x^8 + x^4 + x^3 + x + 1
        private static readonly byte[] mix_matrix = new byte[] { 2, 3, 1, 1 };

        public static byte[] SBox(byte[] state)
        {
            for (int i = 0; i < state.Length; ++i) state[i] = rijndael_sbox[state[i]];
            return state;
        }

        // The AES state is a column-first 4x4 matrix. Demonstrated below are the decimal indices, as would be represented in the state:
        // 00 04 08 12
        // 01 05 09 13
        // 02 06 10 14
        // 03 07 11 15

        // Shiftrows applied to state above:
        // 00 04 08 12  -  No change
        // 05 09 13 01  -  Shifted 1 to the left
        // 10 14 02 06  -  Shifted 2 to the left
        // 15 03 07 11  -  Shifted 3 to the left
        public static byte[] ShiftRows(byte[] state)
        {
            for(int i = 1; i<4; ++i)
            {
                byte tmp = state[i];
                for(int j = 0; j<3; ++j) state[i + j*4] = state[i + ((j + i)%4)*4];
                state[i + 12] = tmp;
            }
            return state;
        }

        // MixColumns provides strong diffusion
        public static byte[] MixColumns(byte[] state)
        {
            byte[] res = new byte[16];

            // Simplified matrix multiplication under GF(2^8)
            for(int i = 0; i<4; ++i)
            {
                for(int j = 0; j<4; ++j)
                {
                    for (int k = 0; k < 4; ++k)
                    {
                        int idx = 4 - j;
                        int r = ((state[k + i * 4] * (mix_matrix[(k + idx) % 4] & 1)) ^ ((state[k + i * 4] << 1) * ((mix_matrix[(k + idx) % 4]>>1)&1)));
                        if (r > 0b100011011) r ^= 0b100011011;
                        res[j + i * 4] ^= (byte) r;
                    }
                }
            }
            return res;
        }

        public static byte[] AddRoundKey(byte[] state, byte[] subkey)
        {
            for (int i = 0; i < state.Length; ++i) state[i] ^= subkey[i];
            return state;
        }

        /// <summary>
        /// Rotate bits to the left by 8 bits. This means that, for example, "0F AB 09 16" becomes "AB 09 16 0F"
        /// </summary>
        /// <param name="i"></param>
        /// <returns></returns>
        public static int Rotate(int i) => ((i >> 24) & 255) & ((i << 8) & ~255);

        public static Tuple<byte[], byte[]> DeriveKey(string message) =>
            new Tuple<byte[], byte[]>(
                new SHA1CryptoServiceProvider().ComputeHash(Encoding.UTF8.GetBytes(message)).ToLength(128),
                new RegularRandomProvider(new Random((int)(new BigInteger(Encoding.UTF8.GetBytes(message)) % int.MaxValue))).GetBytes(new byte[128])
             );




        // Finite field arithmetic helper methods
        private static byte RCON(int i) => i<=0?(byte)0x8d:GF28Mod(i - 1);

        public static byte GF28Mod(int pow)
        {
            byte[] val = new byte[1+(pow/8)];
            val[pow / 8] |= (byte)(1 << (pow % 8));
            return GF28Mod(val);
        }
        private static byte GF28Mod(byte[] value)
        {
            byte[] CA_l;
            while (GT(value, CA_max, true))
            {
                CA_l = NeedsAlignment(value) ? AlignCA(value) : CA;
                byte[] res = new byte[CA_l.Length];
                for (int i = 0; i < CA_l.Length; ++i) res[i] = (byte)(value[i] ^ CA_l[i]);
                value = ClipZeroes(res);
            }
            return value[0];
        }

        /// <summary>
        /// GF(2^8) uses the irreducible polynomial x^8 + x^4 + x^3 + x^1 + x^0 which can be represented as 0001 0001 1011 due to the characteristic of the field
        /// </summary>
        private static readonly byte[] CA = new byte[] { 0b0001_1011, 0b0000_0001 };
        private static readonly byte[] CA_max = new byte[] { 0b0000_0000, 0b0000_0001 };
        private static readonly int CA_FSB = 8;
        private static byte[] AlignCA(byte[] value) => SHL((byte[])CA.Clone(), GetFirstSetBit(value) - CA_FSB);
        private static bool NeedsAlignment(byte[] b) => b.Length > 1 && GetFirstSetBit(b) > CA_FSB;
        private static bool GT(byte[] v1, byte[] v2, bool eq)
        {
            byte[] bigger = v1.Length > v2.Length ? v1 : v2;
            byte[] smaller = v1.Length > v2.Length ? v2 : v1;
            for (int i = Math.Max(bigger.Length, smaller.Length)-1; i >= 0; --i)
                if (i >= smaller.Length && bigger[i] != 0)
                    return bigger == v1;
                else if (i < smaller.Length && bigger[i] != smaller[i])
                    return (bigger[i] > smaller[i]) ^ (bigger != v1);
            return eq;
        }
        private static byte[] ClipZeroes(byte[] val)
        {
            int i = 0; 
            for(int j = val.Length-1; j>=0; --j) if (val[j] != 0) { i = j; break; }
            byte[] res = new byte[i+1];
            Array.Copy(val, res, res.Length);
            return res;
        }

        private static int GetFirstSetBit(byte[] b)
        {
            for (int i = (b.Length * 8) - 1; i >= 0; --i) if ((b[i / 8] & (1 << (i % 8))) != 0) return i;
            return -1;
        }

        private static byte ShiftedBitmask(int start)
        {
            byte res = 0;
            for (int i = start; i > 0; --i) res = (byte)((res >> 1) | 128);
            return res;
        }

        private static byte[] SHL(byte[] value, int shift)
        {
            int set = shift / 8;
            int sub = shift % 8;
            byte bm = ShiftedBitmask(sub);
            byte ibm = (byte) ~bm;
            byte carry = 0;
            int fsb1 = GetFirstSetBit(value);
            if (fsb1 == -1) return value;
            byte fsb = (byte)(fsb1 % 8);
            byte[] create = new byte[value.Length + set + (fsb + set >= 7 ? 1: 0)];
            for(int i = set; i<create.Length; ++i)
            {
                create[i] = (byte)(((value[i - set] & ibm) << sub) | carry);
                carry = (byte)((value[i - set] & bm) >> (8-sub));
            }
            create[create.Length - 1] |= carry;
            return create;
        }
    }
}
