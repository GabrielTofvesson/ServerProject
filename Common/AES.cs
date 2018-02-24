using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Tofvesson.Crypto
{
    public class Rijndael128 : BlockCipher
    {
        protected readonly byte[] roundKeys;
        protected readonly byte[] key;

        public Rijndael128(string key) : base(16)
        {
            // Derive a proper key
            var t = DeriveKey(key, "PlsNoRainbowz");
            this.key = t.Item1;

            // Expand the derived key
            roundKeys = KeySchedule(this.key, BitMode.Bit128);
        }
        protected Rijndael128(byte[] key) : base(16)
        {
            this.key = key;

            // Expand the derived key
            roundKeys = KeySchedule(this.key, BitMode.Bit128);
        }


        // Encrypt/Decrypt a string by just converting it to bytes and passing it along to the byte-based encryption/decryption methods
        public byte[] EncryptString(string message) => Encrypt(Encoding.UTF8.GetBytes(message));
        public string DecryptString(byte[] message, int length) => new string(Encoding.UTF8.GetChars(Decrypt(message, length, false))).Substring(0, length);

        // Encrypt a message (this one jsut splits the message into blocks and passes it along)
        public override byte[] Encrypt(byte[] message)
        {
            byte[] result = new byte[message.Length + ((16 - (message.Length % 16))%16)];
            Array.Copy(message, result, message.Length);
            for(int i = 0; i<result.Length/16; ++i)
                Array.Copy(AES128_Encrypt(result.SubArray(i * 16, i * 16 + 16)), 0, result, i * 16, 16);
            return result;
        }

        // Decrypt a message (these just pass the message along)
        public override byte[] Decrypt(byte[] ciphertext) => Decrypt(ciphertext, -1, false);
        public byte[] Decrypt(byte[] message, int messageLength) => Decrypt(message, messageLength, true);
        protected byte[] Decrypt(byte[] message, int messageLength, bool doTruncate)
        {
            if (message.Length % 16 != 0) throw new SystemException("Invalid encrypted message length!");
            byte[] result = new byte[message.Length];
            Array.Copy(message, result, message.Length);
            for (int i = 0; i < result.Length / 16; ++i)
                Array.Copy(AES128_Decrypt(result.SubArray(i * 16, i * 16 + 16)), 0, result, i * 16, 16);
            return doTruncate ? result.SubArray(0, messageLength) : result;
        }

        // The actual AES encryption implementation
        protected virtual byte[] AES128_Encrypt(byte[] input)
        {
            // The "state" is the name given the the 4x4 matrix that AES encrypts. The state is known as the "state" no matter what stage of AES it has gone through or how many left it has
            byte[] state = new byte[16];
            Array.Copy(input, state, 16);

            // Initial round. Just just xor the key for this round input the input
            state = AddRoundKey(state, roundKeys, 0);

            // Rounds 1 - 9
            for (int rounds = 1; rounds < 10; ++rounds)
            {
                state = ShiftRows(SubBytes(state, false));          // Shift the rows of the column-major matrix
                if (rounds != 9) state = MixColumns(state, true);   // Mix the columns (gonna be honest, I don't remember what this does, but it has something to do with galois fields, so just check Galois2 out)
                state = AddRoundKey(state, roundKeys, rounds * 16); // Xor the key into the mess
            }

            // Now this matrix is encrypted!
            return state;
        }

        // Literally just the inverse functions of the Encrypt-process run in reverse.
        protected virtual byte[] AES128_Decrypt(byte[] input)
        {
            byte[] state = new byte[16];
            Array.Copy(input, state, 16);

            for (int rounds = 9; rounds > 0; --rounds)
            {
                state = AddRoundKey(state, roundKeys, rounds * 16);
                if (rounds != 9) state = MixColumns(state, false);
                state = SubBytes(UnShiftRows(state), true);
            }

            return AddRoundKey(state, roundKeys, 0);
        }

        // Save the key to a file
        public void Save(string baseName, bool force = false)
        {
            if (force || !File.Exists(baseName + ".key")) File.WriteAllBytes(baseName + ".key", key);
        }

        // Load the key from a file (gonna be honest, I think I just copy-pasted this from the RSA file and renamed some stuff)
        public static Rijndael128 Load(string baseName)
        {
            if (!File.Exists(baseName + ".key")) throw new SystemException("Required files could not be located");
            return new Rijndael128(File.ReadAllBytes(baseName + ".key"));
        }

        // De/-serializes the key (the method is just here for compatibility)
        public byte[] Serialize() => Support.SerializeBytes(new byte[][] { key });
        public static Rijndael128 Deserialize(byte[] message, out int read)
        {
            byte[][] output = Support.DeserializeBytes(message, 1);
            read = output[0].Length + 8;
            return new Rijndael128(output[0]);
        }


        // Internal methods for encryption :)
        private static uint KSchedCore(uint input, int iteration)
        {
            input = Rotate(input);
            byte[] bytes = Support.WriteToArray(new byte[4], input, 0);
            for (int i = 0; i < bytes.Length; ++i) bytes[i] = SBox(bytes[i]);
            bytes[bytes.Length - 1] ^= RCON(iteration);
            return (uint)Support.ReadInt(bytes, 0);
        }

        // Rijndael key schedule: implemented for the three common implementations because I'm thorough or something
        public enum BitMode { Bit128, Bit192, Bit256 }
        private static byte[] KeySchedule(byte[] key, BitMode mode)
        {
            int n = mode == BitMode.Bit128 ? 16 : mode == BitMode.Bit192 ? 24 : 32;
            int b = mode == BitMode.Bit128 ? 176 : mode == BitMode.Bit192 ? 208 : 240;

            byte[] output = new byte[b];
            Array.Copy(key, output, n);

            int rcon_iter = 1;

            int accruedBytes = n;
            while (accruedBytes < b)
            {
                // Generate 4 new bytes of extended key
                byte[] t = Support.WriteToArray(new byte[4], KSchedCore((uint)Support.ReadInt(output, accruedBytes - 4), rcon_iter), 0);
                ++rcon_iter;
                for (int i = 0; i < 4; ++i) t[i] ^= output[accruedBytes - n + i];
                Array.Copy(t, 0, output, accruedBytes, 4);
                accruedBytes += 4;

                // Generate 12 new bytes of extended key
                for (int i = 0; i < 3; ++i)
                {
                    Array.Copy(output, accruedBytes - 4, t, 0, 4);
                    for (int j = 0; j < 4; ++j) t[j] ^= output[accruedBytes - n + j];
                    Array.Copy(t, 0, output, accruedBytes, 4);
                    accruedBytes += 4;
                }

                // Special processing for 256-bit key schedule
                if (mode == BitMode.Bit256)
                {
                    Array.Copy(output, accruedBytes - 4, t, 0, 4);
                    for (int j = 0; j < 4; ++j) t[j] = (byte)(SBox(t[j]) ^ output[accruedBytes - n + j]);
                    Array.Copy(t, 0, output, accruedBytes, 4);
                    accruedBytes += 4;
                }
                // Special processing for 192-bit key schedule
                if (mode != BitMode.Bit128)
                    for (int i = mode == BitMode.Bit192 ? 1 : 2; i >= 0; --i)
                    {
                        Array.Copy(output, accruedBytes - 4, t, 0, 4);
                        for (int j = 0; j < 4; ++j) t[j] ^= output[accruedBytes - n + j];
                        Array.Copy(t, 0, output, accruedBytes, 4);
                        accruedBytes += 4;
                    }
            }

            return output;
        }

        // MixColumns matrix basis. Used for multiplication over the rijndael field
        private static readonly byte[] mix_matrix = new byte[] { 2, 3, 1, 1 };
        private static readonly byte[] unmix_matrix = new byte[] { 14, 11, 13, 9 };

        /// <summary>
        /// Rijndael substitution step in the encryption (first thing that happens). This supplies confusion for the algorithm
        /// </summary>
        /// <param name="b">The value (most likely from the AES state) that should be substituted</param>
        /// <returns>The substituted byte</returns>
        private static byte SBox(byte b) => Affine(new Galois2(new byte[] { b }).InvMul().ToByteArray()[0]);

        // Inverse SBox-function
        private static byte ISBox(byte b) => new Galois2(new byte[] { Rffine(b) }).InvMul().ToByteArray()[0];

        // Replaces GF(2^8) matrix multiplication for the affine and reverse affine functions
        private static byte Affine(byte value) => (byte)(value ^ Rot(value, 1) ^ Rot(value, 2) ^ Rot(value, 3) ^ Rot(value, 4) ^ 0b0110_0011);
        private static byte Rffine(byte value) => (byte)(Rot(value, 1) ^ Rot(value, 3) ^ Rot(value, 6) ^ 0b0000_0101);

        // Rotate bitss
        private static byte Rot(byte value, int by) => (byte)((value << by) | (value >> (8 - by)));

        private delegate byte SBOXFunc(byte b);
        private static byte[] SubBytes(byte[] state, bool reverse)
        {
            SBOXFunc v;
            if (reverse) v = ISBox;
            else v = SBox;
            for (int i = 0; i < state.Length; ++i) state[i] = v(state[i]);
            return state;
        }

        // The AES state is a column-major 4x4 matrix (for AES-128). Demonstrated below are the decimal indices, as would be represented in the state:
        // 00 04 08 12
        // 01 05 09 13
        // 02 06 10 14
        // 03 07 11 15

        // Shiftrows applied to state above:
        // 00 04 08 12  -  No change
        // 05 09 13 01  -  Shifted 1 to the left
        // 10 14 02 06  -  Shifted 2 to the left
        // 15 03 07 11  -  Shifted 3 to the left

        /// <summary>
        /// Shifts the rows of the column-major matrix
        /// </summary>
        /// <param name="state"></param>
        /// <returns>The shifted matrix</returns>
        public static byte[] ShiftRows(byte[] state)
        {
            for (int i = 1; i < 4; ++i)
            {
                uint value = GetRow(state, i);
                for (int j = 0; j < i; ++j) value = Rotate(value);
                WriteToRow(value, state, i);
            }
            return state;
        }

        // Reverse ShiftRows
        private static byte[] UnShiftRows(byte[] state)
        {
            for (int i = 1; i < 4; ++i)
            {
                uint value = GetRow(state, i);
                for (int j = 3; j >= i; --j) value = Rotate(value);
                WriteToRow(value, state, i);
            }
            return state;
        }

        // Helper method, really
        private static void WriteToRow(uint value, byte[] to, int row)
        {
            to[row] = (byte)(value & 255);
            to[row + 4] = (byte)((value >> 8) & 255);
            to[row + 8] = (byte)((value >> 16) & 255);
            to[row + 12] = (byte)((value >> 24) & 255);
        }

        // Boring helper method
        private static uint GetRow(byte[] from, int row) => (uint)(from[row] | (from[row + 4] << 8) | (from[row + 8] << 16) | (from[row + 12] << 24));

        /// <summary>
        /// MixColumns adds diffusion to the algorithm. Performs matrix multiplication under GF(2^8) with the irreducible prime 0x11B (x^8 + x^4 + x^3 + x + 1)
        /// </summary>
        /// <param name="state"></param>
        /// <returns>A matrix-multiplied and limited state (mixed)</returns>
        private static byte[] MixColumns(byte[] state, bool mix)
        {
            byte[] res = new byte[16];
            byte[] rowGenerator = mix ? mix_matrix : unmix_matrix;

            // Simplified matrix multiplication under GF(2^8)
            for (int i = 0; i < 4; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    for (int k = 0; k < 4; ++k)
                    {
                        int idx = 4 - j;
                        Galois2 g = Galois2.FromValue(state[k + i * 4]);
                        res[j + i * 4] ^= g.Multiply(Galois2.FromValue(rowGenerator[(k + idx) % 4])).ToByteArray()[0];
                        //int r = ((state[k + i * 4] * (mix_matrix[(k + idx) % 4] & 1)) ^ ((state[k + i * 4] << 1) * ((mix_matrix[(k + idx) % 4]>>1)&1)));
                        //if (r > 0b100011011) r ^= 0b100011011;
                        //res[j + i * 4] ^= (byte) r;
                    }
                }
            }
            return res;
        }

        /// <summary>
        /// Introduces the subkey for this round to the state
        /// </summary>
        /// <param name="state">The state to introduce the roundkey to</param>
        /// <param name="subkey">The subkey</param>
        /// <returns>The state where the roundkey has been added</returns>
        private static byte[] AddRoundKey(byte[] state, byte[] subkey, int offset)
        {
            for (int i = 0; i < state.Length; ++i) state[i] ^= subkey[i + offset];
            return state;
        }

        /// <summary>
        /// Rotate bits to the left by 8 bits. This means that, for example, "0F AB 09 16" becomes "AB 09 16 0F"
        /// </summary>
        /// <param name="i"></param>
        /// <returns>Rotated value</returns>
        private static uint Rotate(uint i) => (uint)(((i >> 24) & 255) | ((i << 8) & ~255));

        /// <summary>
        /// KDF for a given input string.
        /// </summary>
        /// <param name="message">Input string to derive key from</param>
        /// <returns>A key and an IV</returns>
        private static Tuple<byte[], byte[]> DeriveKey(string message, string salt)
        {
            byte[] key = KDF.PBKDF2(KDF.HMAC_SHA1, Encoding.UTF8.GetBytes(message), salt.ToUTF8Bytes(), 4096, 16); // Generate a 16-byte (128-bit) key from salt over 4096 iterations of HMAC-SHA1
            return new Tuple<byte[], byte[]>(key, salt.ToUTF8Bytes());
        }

        private static byte RCON(int i) => i <= 0 ? (byte)0x8d : new Galois2(i - 1).ToByteArray()[0];
    }



    // If you genuinely care what this does, to which I would under regular circumstances call you a nerd but alas I researched this, soooooo here:
    // https://en.wikipedia.org/wiki/Finite_field_arithmetic
    // http://www.cs.utsa.edu/~wagner/laws/FFM.html
    // https://www.wolframalpha.com/examples/math/algebra/finite-fields/
    // https://www.youtube.com/watch?v=x1v2tX4_dkQ
    // That YouTube link explains it the best imo, but the others really help and solidify the concept.
    // Essentially, if you're genuinely going to torture yourself by trying to learn this stuff, at least do yourself a favour and start with the video.
    // Also, I'm not gonna comment the code down there because it's a hellhole and it's late and I have a headache and ooooooooohhhhh I don't want to spend more time that I already have on that stuff.
    // You get the comments that I put there when I made this; no more than that! Honestly, they're still plenty so just make do!
    /// <summary>
    /// Object representation of a Galois Field with characteristic 2
    /// </summary>
    public class Galois2
    {
        private static readonly byte[] ZERO = new byte[1] { 0 };
        private static readonly byte[] ONE = new byte[1] { 1 };

        public static byte[] RijndaelIP
        { get { return new byte[] { 0b0001_1011, 0b0000_0001 }; } }

        protected readonly byte[] value;
        protected readonly byte[] ip;

        /// <summary>
        /// Create a new Galois2 instance representing the given polynomial using the given irreducible polynomial. The given value will be reduced if possible
        /// </summary>
        /// <param name="value">Value to represent</param>
        /// <param name="ip">Irreducible polynomial</param>
        public Galois2(byte[] value, byte[] ip)
        {
            this.value = _ClipZeroes(_FieldMod(value, this.ip = ip));
        }

        public Galois2(int pow, byte[] ip) : this(_FlipBit(new byte[0], pow), ip)
        { }

        public Galois2(byte[] value) : this(value, RijndaelIP)
        { }

        public Galois2(int pow) : this(pow, RijndaelIP)
        { }

        public static Galois2 FromValue(int value, byte[] ip) => new Galois2(Support.WriteToArray(new byte[4], value, 0), ip);
        public static Galois2 FromValue(int value) => FromValue(value, Galois2.RijndaelIP);

        public Galois2 Multiply(Galois2 factor) => new Galois2(_Mul(value, factor.value), ip);
        public Galois2 Add(Galois2 val) => new Galois2(_Add(value, val.value), ip);
        public Galois2 Subtract(Galois2 val) => new Galois2(_Sub(value, val.value), ip);
        public Galois2 XOR(Galois2 val) => new Galois2(_XOR(value, val.value), ip);

        /// <summary>
        /// Perform inverse multiplication on this Galois2 object. This is done by performing the extended euclidean algorithm (two-variable linear diophantine equations).
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public Galois2 InvMul()
        {
            if (_ArraysEquals(value, ZERO)) return FromValue(0, ip);
            Stack<byte[]> factors = new Stack<byte[]>();
            byte[] val = value;
            byte[] mod = ip;
            ModResult res;
            while (!_ArraysEquals((res = _Mod(val, mod)).rem, ZERO))
            {
                factors.Push(res.div);
                val = mod;
                mod = res.rem;
            }

            // Values are not coprime. There is no solution!
            if (!_ArraysEquals(mod, ONE)) return new Galois2(new byte[0], ip);

            byte[] useful = new byte[1] { 1 };
            byte[] theOtherOne = factors.Pop();
            byte[] tmp;
            while (factors.Count > 0)
            {
                tmp = theOtherOne;
                theOtherOne = _Add(useful, _Mul(theOtherOne, factors.Pop()));
                useful = tmp;
            }
            return new Galois2(useful, ip);
        }

        public byte[] ToByteArray() => (byte[])value.Clone();
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            for (int i = _GetFirstSetBit(value); i >= 0; --i)
                if (_BitAt(value, i))
                    builder.Append("x^").Append(i).Append(" + ");
            if (builder.Length == 0) builder.Append("0 ");
            else builder.Remove(builder.Length - 2, 2);
            builder.Append("(mod ");
            int j;
            for(int i = j = _GetFirstSetBit(ip); i>=0; --i)
                if (_BitAt(ip, i))
                    builder.Append("x^").Append(i).Append(" + ");
            if (j == -1) builder.Append('0');
            else builder.Remove(builder.Length - 3, 3);

            return builder.Append(')').ToString();
        }

        // Overrides
        public override bool Equals(object obj)
        {
            if (obj == null || !(obj is Galois2 || obj is byte[])) return false;

            byte[] val = obj is Galois2 ? ((Galois2)obj).value : (byte[])obj;

            bool cmp = val.Length > value.Length;
            byte[] bigger = cmp ? val : value;
            byte[] smaller = cmp ? value : val;
            for (int i = bigger.Length - 1; i >= 0; --i)
                if (i >= smaller.Length)
                {
                    if (bigger[i] != 0) return false;
                }
                else if (bigger[i] != smaller[i]) return false;

            // If the value supplied was a byte array, ignore the irreducible prime, otherwise, make sure the irreducible primes are the same
            return obj is byte[] || ((Galois2)obj).ip.Equals(ip);
        }

        public override int GetHashCode()
        {
            var hashCode = -579181322;
            hashCode = hashCode * -1521134295 + EqualityComparer<byte[]>.Default.GetHashCode(value);
            hashCode = hashCode * -1521134295 + EqualityComparer<byte[]>.Default.GetHashCode(ip);
            return hashCode;
        }


        // Just internal stuff from here on out boiiiiiiis!



        protected static bool _ArraysEquals(byte[] v1, byte[] v2)
        {
            bool cmp = v1.Length > v2.Length;
            byte[] bigger = cmp ? v1 : v2;
            byte[] smaller = cmp ? v2 : v1;
            for (int i = bigger.Length - 1; i >= 0; --i)
                if (i >= smaller.Length)
                {
                    if (bigger[i] != 0) return false;
                }
                else if (bigger[i] != smaller[i]) return false;
            return true;
        }

        // Internal methods for certain calculations
        protected static byte[] _FieldMod(byte[] applyTo, byte[] fieldIP)
        {
            byte[] CA_l;
            int fsb = _GetFirstSetBit(fieldIP);
            while (_GetFirstSetBit(applyTo) >= fsb) // In GF(2^8), polynomials may not exceed x^7. This means that a value containing a bit representing x^8 or higher is invalid
            {
                CA_l = _GetFirstSetBit(applyTo) >= _GetFirstSetBit(fieldIP) ? _Align((byte[])fieldIP.Clone(), applyTo) : fieldIP;
                byte[] res = new byte[CA_l.Length];
                for (int i = 0; i < CA_l.Length; ++i) res[i] = (byte)(applyTo[i] ^ CA_l[i]);
                applyTo = _ClipZeroes(res);
            }
            return applyTo;
        }


        /// <summary>
        /// Remove preceding zero-bytes
        /// </summary>
        /// <param name="val">Value to remove preceding zeroes from</param>
        /// <returns>Truncated value (if truncation was necessary)</returns>
        protected static byte[] _ClipZeroes(byte[] val)
        {
            int i = 0;
            for (int j = val.Length - 1; j >= 0; --j) if (val[j] != 0) { i = j; break; }
            byte[] res = new byte[i + 1];
            Array.Copy(val, res, res.Length);
            return res;
        }



        /// <summary>
        /// Get the bit index of the highest bit. This will get the value of the exponent, i.e. index 8 represents x^8
        /// </summary>
        /// <param name="b">Value to get the highest set bit from</param>
        /// <returns>Index of the highest set bit. -1 if no bits are set</returns>
        protected static int _GetFirstSetBit(byte[] b)
        {
            for (int i = (b.Length * 8) - 1; i >= 0; --i)
                if (b[i / 8] == 0) i -= i % 8; // Speeds up searches through blank bytes
                else if ((b[i / 8] & (1 << (i % 8))) != 0)
                    return i;
            return -1;
        }

        /// <summary>
        /// Get the state of a bit in the supplied value.
        /// </summary>
        /// <param name="value">Value to get bit from</param>
        /// <param name="index">Bit index to get bit from. (Not byte index)</param>
        /// <returns></returns>
        protected static bool _BitAt(byte[] value, int index) => (value[index / 8] & (1 << (index % 8))) != 0;

        protected static byte _ShiftedBitmask(int start)
        {
            byte res = 0;
            for (int i = start; i > 0; --i) res = (byte)((res >> 1) | 128);
            return res;
        }


        protected static byte[] _Align(byte[] value, byte[] to) => _SHL(value, _GetFirstSetBit(to) - _GetFirstSetBit(value));
        protected static bool _NeedsAlignment(byte[] value, byte[] comp) => _GetFirstSetBit(value) > _GetFirstSetBit(comp);
        protected static bool _GT(byte[] v1, byte[] v2, bool eq)
        {
            byte[] bigger = v1.Length > v2.Length ? v1 : v2;
            byte[] smaller = v1.Length > v2.Length ? v2 : v1;
            for (int i = bigger.Length - 1; i >= 0; --i)
                if (i >= smaller.Length && bigger[i] != 0)
                    return bigger == v1;
                else if (i < smaller.Length && bigger[i] != smaller[i])
                    return (bigger[i] > smaller[i]) ^ (bigger != v1);
            return eq;
        }



        /// <summary>
        /// Shifts bit in the array by 'shift' bits to the left. This means that 0b0010_0000_1000_1111 shited by 2 becomes 0b1000_0010_0011_1100. 
        /// Note: A shift of 0 just acts like a slow value.Clone()
        /// </summary>
        /// <param name="value"></param>
        /// <param name="shift"></param>
        /// <returns></returns>
        protected static byte[] _SHL(byte[] value, int shift)
        {
            int set = shift / 8;
            int sub = shift % 8;
            byte bm = _ShiftedBitmask(sub);
            byte ibm = (byte)~bm;
            byte carry = 0;
            int fsb1 = _GetFirstSetBit(value);
            if (fsb1 == -1) return value;
            byte fsb = (byte)(fsb1 % 8);
            byte[] create = new byte[value.Length + set + (fsb + sub >= 7 ? 1 : 0)];
            for (int i = set; i - set < value.Length; ++i)
            {
                create[i] = (byte)(((value[i - set] & ibm) << sub) | carry);
                carry = (byte)((value[i - set] & bm) >> (8 - sub));
            }
            create[create.Length - 1] |= carry;
            return create;
        }


        /// <summary>
        /// Flips the bit at the given binary index in the supplied value. For example, flipping bit 5 in the number 0b0010_0011 would result in 0b0000_0011, whereas flipping index 7 would result in 0b1010_0011.
        /// </summary>
        /// <param name="value">Value to manipulate bits of</param>
        /// <param name="bitIndex">Index (in bits) of the bit to flip.</param>
        /// <returns>An array (may be the same object as the one given) with a bit flipped.</returns>
        protected static byte[] _FlipBit(byte[] value, int bitIndex)
        {
            if (bitIndex >= value.Length * 8)
            {
                byte[] intermediate = new byte[(bitIndex / 8) + 1];
                Array.Copy(value, intermediate, value.Length);
                value = intermediate;
            }
            value[bitIndex / 8] ^= (byte)(1 << (bitIndex % 8));
            return value;
        }




        // Addition, Subtraction and XOR are all equivalent under GF(2^8) due to the modular nature of the field
        protected static byte[] _Add(byte[] v1, byte[] v2) => _XOR(v1, v2);
        protected static byte[] _Sub(byte[] v1, byte[] v2) => _XOR(v1, v2);
        protected static byte[] _XOR(byte[] v1, byte[] v2)
        {
            bool size = v1.Length > v2.Length;
            byte[] bigger = size ? v1 : v2;
            byte[] smaller = size ? v2 : v1;
            byte[] res = new byte[bigger.Length];
            Array.Copy(bigger, res, bigger.Length);
            for (int i = 0; i < smaller.Length; ++i) res[i] ^= smaller[i];
            return _ClipZeroes(res);
        }

        /// <summary>
        /// Perform polynomial multiplication under a galois field with characteristic 2
        /// </summary>
        /// <param name="value">Factor to multiply</param>
        /// <param name="by">Factor to multiply other value by</param>
        /// <returns>The product of the multiplication</returns>
        protected static byte[] _Mul(byte[] value, byte[] by)
        {
            byte[] result = new byte[0];
            for (int i = _GetFirstSetBit(by); i >= 0; --i)
                if (_BitAt(by, i))
                    result = _Add(result, _SHL(value, i));
            return result;
        }

        /// <summary>
        /// Performs modulus on a given value by a certain value (mod) over a Galois Field with characteristic 2. This method performs both modulus and division.
        /// </summary>
        /// <param name="value">Value to perform modular aithmetic on</param>
        /// <param name="mod">Modular value</param>
        /// <returns>The result of the polynomial division and the result of the modulus</returns>
        protected static ModResult _Mod(byte[] value, byte[] mod)
        {
            byte[] divRes = new byte[1];
            while (_GT(value, mod, true))
            {
                divRes = _FlipBit(divRes, _GetFirstSetBit(value) - _GetFirstSetBit(mod)); // Notes the bit shift in the division tracker
                value = _Sub(value, _Align(mod, value));
            }
            return new ModResult(divRes, value);
        }

        /// <summary>
        /// Used to store the result of a polynomial division/modulus in GF(2^m)
        /// </summary>
        protected struct ModResult
        {
            public ModResult(byte[] div, byte[] rem)
            {
                this.div = div;
                this.rem = rem;
            }
            public byte[] div;
            public byte[] rem;
        }
    }
}
