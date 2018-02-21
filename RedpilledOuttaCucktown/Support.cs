using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Tofvesson.Crypto
{
    public static class Support
    {
        //   --    Math    --
        public static BigInteger Invert(BigInteger b)
        {
            byte[] arr = b.ToByteArray();
            for (int i = 0; i < arr.Length; ++i) arr[i] ^= 255;
            BigInteger integer = new BigInteger(arr);
            integer += 1;
            return integer;
        }

        public static BigInteger ModExp(BigInteger b, BigInteger e, BigInteger m)
        {
            int count = e.ToByteArray().Length * 8;
            BigInteger result = BigInteger.One;
            b = b % m;
            while (count>0)
            {
                if (e % 2 != 0) result = (result * b) % m;
                b = (b * b) % m;
                e >>= 1;
                --count;
            }
            return result;
        }

        /// <summary>
        /// Uses the fermat test a given amount of times to test whether or not a supplied interger is probably prime.
        /// </summary>
        /// <param name="b">Value to test primality of</param>
        /// <param name="provider">Random provider used to generate values to test b against</param>
        /// <param name="certainty">How many times the test should be performed. More iterations means higher certainty, but at the cost of performance!</param>
        /// <returns>Whether or not the given value is probably prime or not</returns>
        public static bool IsProbablePrime(BigInteger b, RandomProvider provider, int certainty)
        {
            BigInteger e = b - 1;
            byte[] b1 = b.ToByteArray();
            byte last = b1[b1.Length-1];
            int len = b1.Length - 1;
            for (int i = 0; i < certainty; ++i)
            {
                byte[] gen = new byte[provider.NextInt(len)+1];
                provider.GetBytes(gen);
                if (last != 0 && gen.Length==len+1) gen[gen.Length - 1] %= last;
                else gen[gen.Length - 1] &= 127;
                
                BigInteger test = new BigInteger(gen);
                if (ModExp(test, e, b) != 1) return false;
            }
            return true;
        }

        /// <summary>
        /// Calculate the greatest common divisor for two values.
        /// </summary>
        /// <param name="b1">First value</param>
        /// <param name="b2">Second value</param>
        /// <returns>The greatest common divisor</returns>
        public static BigInteger GCD(BigInteger b1, BigInteger b2)
        {
            BigInteger tmp;
            while ((tmp = b1 % b2) != 0)
            {
                b1 = b2;
                b2 = tmp;
            }
            return b2;
        }

        /// <summary>
        /// Linear diophantine equations. Calculates the modular multiplicative inverse for a given value and a given modulus.
        /// For: ax + by = 1
        /// Where 'a' and 'b' are known factors
        /// </summary>
        /// <param name="in1">First known factor (a)</param>
        /// <param name="in2">Second known factor (b)</param>
        /// <returns>A pair of factors that fulfill the aforementioned equations (if possible), where Item1 corresponds to 'x' and Item2 corresponds to 'y'. If the two supplied known factors are not coprime, both factors will be 0</returns>
        public static KeyValuePair<BigInteger, BigInteger> Dio(BigInteger in1, BigInteger in2)
        {
            // Euclidean algorithm
            BigInteger tmp;
            var i1 = in1;
            var i2 = in2;
            if (i1 <= BigInteger.Zero || i2 <= BigInteger.Zero || i1 == i2 || i1 % i2 == BigInteger.Zero || i2 % i1 == BigInteger.Zero)
            {
                return new KeyValuePair<BigInteger, BigInteger>(BigInteger.Zero, BigInteger.Zero);
            }
            var minusOne = new BigInteger(-1);
            var e_m = new BigInteger(-1L);
            var collect = new Stack<BigInteger>();
            while ((e_m = i1 % i2) != BigInteger.Zero)
            {
                collect.Push(i1 / i2 * minusOne);
                i1 = i2;
                i2 = e_m;
            }

            // There are no solutions because 'a' and 'b' are not coprime
            if (i2 != BigInteger.One)
                return new KeyValuePair<BigInteger, BigInteger>(BigInteger.Zero, BigInteger.Zero);


            // Extended euclidean algorithm
            var restrack_first = BigInteger.One;
            var restrack_second = collect.Pop();

            while (collect.Count > 0)
            {
                tmp = restrack_second;
                restrack_second = restrack_first + restrack_second * collect.Pop();
                restrack_first = tmp;
            }
            return new KeyValuePair<BigInteger, BigInteger>(restrack_first, restrack_second);
        }

        /// <summary>
        /// Generate a prime number using with a given approximate length and byte length margin
        /// </summary>
        /// <param name="threads">How many threads to use to generate primes</param>
        /// <param name="approximateByteCount">The byte array length around which the prime generator will select lengths</param>
        /// <param name="byteMargin">Allowed deviation of byte length from approximateByteCount</param>
        /// <param name="certainty">How many iterations of the fermat test should be run to test primailty for each generated number</param>
        /// <param name="provider">Random provider that will be used to generate random primes</param>
        /// <returns>A prime number that is aproximately approximateByteCount long</returns>
        public static BigInteger GeneratePrime(int threads, int approximateByteCount, int byteMargin, int certainty, RandomProvider provider)
        {
            var found = false;
            BigInteger result = BigInteger.Zero;
            for(int i = 0; i<threads; ++i)
                Task.Factory.StartNew(() =>
                {
                    char left = '\0';
                    byte rand = 0;
                    BigInteger b = BigInteger.Zero;
                    while (!found)
                    {
                        if (left == 0)
                        {
                            rand = provider.GetBytes(1)[0];
                            left = (char)8;
                        }

                        byte[] b1 = provider.GetBytes(approximateByteCount + (provider.GetBytes(1)[0] % byteMargin) * (rand % 2 == 1 ? 1 : -1));
                        b1[0] |= 1;  // Always odd
                        b1[b1.Length - 1] &= 127;  // Always positive
                        b = new BigInteger(b1);
                        rand >>= 1;
                        --left;
                        if (IsProbablePrime(b, provider, certainty))
                        {
                            found = true;
                            result = b;
                        }
                    }
                });
            while (!found) System.Threading.Thread.Sleep(125);
            return result;
        }



        //  --    Net    --
        /// <summary>
        /// Finds an IPv4a address in the address list.
        /// </summary>
        /// <param name="entry">IPHostEntry to get the address from</param>
        /// <returns>An IPv4 address if available, otherwise null</returns>
        public static IPAddress GetIPV4(this IPHostEntry entry)
        {
            foreach (IPAddress addr in entry.AddressList)
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    return addr;
            return null;
        }


        //   --    Arrays/Collections    --
        /// <summary>
        /// Pad or truncate this array to the specified length. Padding is performed by filling the new indicies with 0's. Truncation removes bytes from the end.
        /// </summary>
        /// <typeparam name="T">The array type</typeparam>
        /// <param name="t">The array to resize</param>
        /// <param name="length">Target length</param>
        /// <returns>A resized array</returns>
        public static T[] ToLength<T>(this T[] t, int length)
        {
            var t1 = new T[length];
            Array.Copy(t, t1, Math.Min(length, t.Length));
            return t1;
        }

        /// <summary>
        /// Reads a serialized 32-bit integer from the byte collection
        /// </summary>
        /// <param name="data"></param>
        /// <param name="offset"></param>
        /// <returns></returns>
        public static int ReadInt(IEnumerable<byte> data, int offset)
        {
            int result = 0;
            for (int i = 0; i < 4; ++i)
                result |= data.ElementAt(i + offset) << (i * 8);
            return result;
        }

        public static int ArrayContains(byte[] b, byte[] seq, bool fromStart = true)
        {
            int track = 0;
            for (int i = fromStart ? 0 : b.Length - 1; (fromStart && i < b.Length) || (!fromStart && i >= 0); i+=fromStart?1:-1)
                if (b[i] == seq[fromStart?track:seq.Length - 1 - track])
                {
                    if (++track == seq.Length) return i;
                }
                else track = 0;
            return -1;
        }

        public static byte[] WriteToArray(byte[] target, int data, int offset)
        {
            for (int i = 0; i < 4; ++i)
                target[i + offset] = (byte)((data >> (i * 8))&255);
            return target;
        }

        public static byte[] WriteContiguous(byte[] target, int offset, params int[] data)
        {
            for (int i = 0; i < data.Length; ++i) WriteToArray(target, data[i], offset + i * 4);
            return target;
        }

        public static byte[] WriteToArray(byte[] target, uint data, int offset)
        {
            for (int i = 0; i < 4; ++i)
                target[i + offset] = (byte)((data >> (i * 8)) & 255);
            return target;
        }

        public static byte[] WriteContiguous(byte[] target, int offset, params uint[] data)
        {
            for (int i = 0; i < data.Length; ++i) WriteToArray(target, data[i], offset + i * 4);
            return target;
        }

        public static byte[] Concatenate(params byte[][] bytes)
        {
            int alloc = 0;
            foreach (byte[] b in bytes) alloc += b.Length;
            byte[] result = new byte[alloc];
            alloc = 0;
            for(int i = 0; i<bytes.Length; ++i)
            {
                Array.Copy(bytes[i], 0, result, alloc, bytes[i].Length);
                alloc += bytes[i].Length;
            }
            return result;
        }

        public static void ArrayCopy<T>(IEnumerable<T> source, int sourceOffset, T[] destination, int offset, int length)
        {
            for (int i = 0; i < length; ++i) destination[i + offset] = source.ElementAt<T>(i+sourceOffset);
        }

        public static string ArrayToString(byte[] array)
        {
            StringBuilder builder = new StringBuilder().Append('[');
            for (int i = 0; i < array.Length; ++i)
            {
                builder.Append(array[i]);
                if (i != array.Length - 1) builder.Append(", ");
            }
            return builder.Append(']').ToString();
        }

        public static void EnqueueAll<T>(this Queue<T> q, IEnumerable<T> items, int offset, int length)
        {
            for (int i = 0; i < length; ++i) q.Enqueue(items.ElementAt(i+offset));
        }
        public static T[]Dequeue<T>(this Queue<T> q, int count)
        {
            T[] t = new T[count];
            for (int i = 0; i < count; ++i) t[i] = q.Dequeue();
            return t;
        }

        public static byte[] SerializeBytes(byte[][] bytes)
        {
            int collectSize = 0;
            for (int i = 0; i < bytes.Length; ++i) collectSize += bytes[i].Length;
            byte[] output = new byte[collectSize + 4*bytes.Length];
            collectSize = 0;
            for(int i = 0; i<bytes.Length; ++i)
            {
                WriteToArray(output, bytes[i].Length, collectSize);
                Array.Copy(bytes[i], 0, output, collectSize + 4, bytes[i].Length);
                collectSize += bytes[i].Length + 4;
            }
            return output;
        }

        public static byte[][] DeserializeBytes(byte[] message, int messageCount)
        {
            byte[][] output = new byte[messageCount][];
            int offset = 0;
            for(int i = 0; i< messageCount; ++i)
            {
                int size = ReadInt(message, offset);
                if (size > message.Length - offset - 4 || (i!=messageCount-1 && size==message.Length-offset-4))
                    throw new IndexOutOfRangeException("Attempted to read more bytes than are available");
                offset += 4;
                output[i] = new byte[size];
                Array.Copy(message, offset, output[i], 0, size);
                offset += size;
            }
            return output;
        }

        public static T[] SubArray<T>(this T[] array, int start, int end)
        {
            T[] res = new T[end-start];
            for (int i = start; i < end; ++i) res[i - start] = array[i];
            return res;
        }


        //  --    Misc    --
        // Allows deconstruction when iterating over a collection of Tuples
        public static void Deconstruct<T1, T2>(this Tuple<T1, T2> tuple, out T1 key, out T2 value)
        {
            key = tuple.Item1;
            value = tuple.Item2;
        }
        public static XmlNode ContainsNamedNode(string name, XmlNodeList lst)
        {
            for (int i = lst.Count - 1; i >= 0; --i)
                if (lst.Item(i).Name.Equals(name))
                    return lst.Item(i);
            return null;
        }
        
        // Swap endianness of a given integer
        public static uint SwapEndian(uint value) => (uint)(((value >> 24) & (255 << 0)) | ((value >> 8) & (255 << 8)) | ((value << 8) & (255 << 16)) | ((value << 24) & (255 << 24)));

        public static string ToHexString(byte[] value)
        {
            StringBuilder builder = new StringBuilder();
            foreach(byte b in value)
            {
                builder.Append((char)((((b >> 4) < 10) ? 48 : 87) + (b >> 4)));
                builder.Append((char)((((b & 15) < 10) ? 48 : 87) + (b & 15)));
            }
            return builder.ToString();
        }

        public static bool ReadYNBool(this TextReader reader, string nonDefault) => reader.ReadLine().ToLower().Equals(nonDefault);
    }

    public static class RandomSupport
    {
        public static BigInteger GenerateBoundedRandom(BigInteger max, RandomProvider provider)
        {
            byte[] b = max.ToByteArray();
            byte maxLast = b[b.Length - 1];
            provider.GetBytes(b);
            if(maxLast!=0) b[b.Length - 1] %= maxLast;
            b[b.Length - 1] |= 127;
            return new BigInteger(b);
        }
    }

    public sealed class RegularRandomProvider : RandomProvider
    {
        private Random rand;
        public RegularRandomProvider(Random rand) { this.rand = rand; }
        public RegularRandomProvider() : this(new Random(Environment.TickCount)) {}

        // Copy our random reference to the other provider: share a random object
        public void share(RegularRandomProvider provider) => provider.rand = this.rand;

        public override byte[] GetBytes(int count) => GetBytes(new byte[count]);

        public override byte[] GetBytes(byte[] buffer)
        {
            rand.NextBytes(buffer);
            return buffer;
        }
    }

    public sealed class CryptoRandomProvider : RandomProvider
    {
        private RNGCryptoServiceProvider rand;
        public CryptoRandomProvider(RNGCryptoServiceProvider rand) { this.rand = rand; }
        public CryptoRandomProvider() : this(new RNGCryptoServiceProvider()) { }

        // Copy our random reference to the other provider: share a random object
        public void share(CryptoRandomProvider provider) => provider.rand = this.rand;

        public override byte[] GetBytes(int count) => GetBytes(new byte[count]);

        public override byte[] GetBytes(byte[] buffer)
        {
            rand.GetBytes(buffer);
            return buffer;
        }
    }

    public sealed class DummyRandomProvider : RandomProvider
    {
        public override byte[] GetBytes(int count) => new byte[count];

        public override byte[] GetBytes(byte[] buffer)
        {
            for (int i = 0; i < buffer.Length; ++i) buffer[i] = 0;
            return buffer;
        }
    }

    public abstract class RandomProvider
    {
        public abstract byte[] GetBytes(int count);
        public abstract byte[] GetBytes(byte[] buffer);

        // Randomly generates a shortinteger bounded by the supplied integer. If bounding value is <= 0, it will be ignored
        public ushort NextUShort(ushort bound = 0)
        {
            byte[] raw = GetBytes(2);
            ushort result = 0;
            for (byte s = 0; s < 2; ++s)
            {
                result <<= 8;
                result |= raw[s];
            }
            return (ushort) (bound > 0 ? result % bound : result);
        }

        // Randomly generates an integer bounded by the supplied integer. If bounding value is <= 0, it will be ignored
        public uint NextUInt(uint bound = 0)
        {
            byte[] raw = GetBytes(4);
            uint result = 0;
            for (byte s = 0; s < 4; ++s)
            {
                result <<= 8;
                result |= raw[s];
            }
            return bound > 0 ? result % bound : result;
        }

        // Randomly generates a long integer bounded by the supplied integer. If bounding value is <= 0, it will be ignored
        public ulong NextULong(ulong bound = 0)
        {
            byte[] raw = GetBytes(8);
            ulong result = 0;
            for (byte s = 0; s < 8; ++s)
            {
                result <<= 8;
                result |=raw[s];
            }
            return bound > 0 ? result % bound : result;
        }

        public short NextShort(short bound = 0) => (short)NextUInt((ushort)bound);
        public int NextInt(int bound = 0) => (int) NextUInt((uint) bound);
        public long NextLong(long bound = 0) => (long)NextULong((ulong)bound);
    }
}
