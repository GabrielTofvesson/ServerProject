using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tofvesson.Crypto
{
    public abstract class BlockCipher
    {
        public Int32 BlockSize { get; private set; }
        public BlockCipher(int blockSize)
        {
            this.BlockSize = blockSize;
        }
        public abstract byte[] Encrypt(byte[] message);
        public abstract byte[] Decrypt(byte[] ciphertext);
    }

    
    public abstract class GenericCBC : BlockCipher
    {
        private readonly byte[] iv_e;
        public byte[] IV { get => (byte[])iv_e.Clone(); }

        protected readonly byte[] currentIV_e;
        protected readonly byte[] currentIV_d;
        protected readonly BlockCipher cipher;
        protected readonly RandomProvider provider;

        public GenericCBC(BlockCipher cipher, RandomProvider provider) : base(cipher.BlockSize)
        {
            this.cipher = cipher;
            this.provider = provider;

            // Generate initialization vector and set it as the current iv
            iv_e = provider.GetBytes(new byte[cipher.BlockSize]);
            currentIV_e = new byte[cipher.BlockSize];
            currentIV_d = new byte[cipher.BlockSize];
            Array.Copy(iv_e, currentIV_e, iv_e.Length);
            Array.Copy(iv_e, currentIV_d, iv_e.Length);
        }

        protected byte[][] SplitBlocks(byte[] message)
        {
            byte[][] blocks = new byte[(message.Length / cipher.BlockSize) + (message.Length % cipher.BlockSize == 0 ? 0 : 1)][];
            for (int i = 0; i < blocks.Length; ++i)
            {
                blocks[i] = message.SubArray(i * cipher.BlockSize, Math.Min((i + 1) * cipher.BlockSize, message.Length));
                if (blocks[i].Length != cipher.BlockSize)
                {
                    byte[] res = new byte[cipher.BlockSize];
                    Array.Copy(blocks[i], res, blocks[i].Length);
                    blocks[i] = res;
                }
            }
            return blocks;
        }

        protected byte[] CollectBlocks(byte[][] result)
        {
            byte[] collected = new byte[result.Length * cipher.BlockSize];
            for (int i = 0; i < result.Length; ++i) Array.Copy(result[i], 0, collected, cipher.BlockSize * i, cipher.BlockSize);
            return collected;
        }

        // Resets the state of this CBC instance
        public virtual void Reset()
        {
            Array.Copy(iv_e, currentIV_e, iv_e.Length);
            Array.Copy(iv_e, currentIV_d, iv_e.Length);
        }
    }

    /// <summary>
    /// Standard cipher block chaining implementation (not recommended, but available nonetheless)
    /// </summary>
    public class CBC : GenericCBC
    {
        public CBC(BlockCipher cipher, RandomProvider provider) : base(cipher, provider)
        { }

        public override byte[] Encrypt(byte[] message)
        {
            byte[][] blocks = SplitBlocks(message);

            for (int i = 0; i < blocks.Length; ++i)
            {
                byte[] enc_result = cipher.Encrypt(blocks[i].XOR(currentIV_e));
                Array.Copy(enc_result, currentIV_e, enc_result.Length);
                Array.Copy(enc_result, blocks[i], cipher.BlockSize);
            }

            return CollectBlocks(blocks);
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            // Split ciphertext into encrypted blocks
            byte[][] blocks = SplitBlocks(ciphertext);

            for(int i = 0; i<blocks.Length; ++i)
            {
                // Decrypt block
                Array.Copy(cipher.Decrypt(blocks[i]).XOR(currentIV_d), blocks[i], cipher.BlockSize);

                // Set the next iv to be this iteration's decrypted block
                Array.Copy(blocks[i], currentIV_d, cipher.BlockSize);
            }

            return CollectBlocks(blocks);
        }
    }

    public class PCBC : GenericCBC
    {
        public PCBC(BlockCipher cipher, RandomProvider provider) : base(cipher, provider)
        { }

        public override byte[] Encrypt(byte[] message)
        {
            byte[][] blocks = SplitBlocks(message);

            for (int i = 0; i < blocks.Length; ++i)
            {
                // Store the unmodified input text block
                byte[] before = (byte[])blocks[i].Clone();

                // Compute the encrypted value for this block
                byte[] enc_result = cipher.Encrypt(blocks[i].XOR(currentIV_e));

                // Store/compute new IV
                Array.Copy(enc_result, currentIV_e, enc_result.Length);
                currentIV_e.XOR(before);

                // Store encryption result
                Array.Copy(enc_result, 0, blocks[i], i * 16, 16);
            }

            return CollectBlocks(blocks);
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            // Split ciphertext into blocks (ciphertext should ahve a length that is a multiple of cipher.BlockSize)
            byte[][] blocks = SplitBlocks(ciphertext);

            // Decrypt each block
            for (int i = 0; i < blocks.Length; ++i)
            {
                // Temporarily store a copy of the encrypted block
                byte[] before = (byte[])blocks[i].Clone();

                // Decrypt the block
                Array.Copy(cipher.Decrypt(before).XOR(currentIV_d), blocks[i], cipher.BlockSize);

                // Compute the next IV
                Array.Copy(currentIV_d, before.XOR(blocks[i]), cipher.BlockSize);
            }

            return CollectBlocks(blocks);
        }
    }

    public class CFB : GenericCBC
    {
        public CFB(BlockCipher cipher, RandomProvider provider) : base(cipher, provider)
        { }

        public override byte[] Encrypt(byte[] message)
        {
            byte[][] blocks = SplitBlocks(message);

            for (int i = 0; i < blocks.Length; ++i)
                // Encrypt IV and compute the XOR of the result with the plaintext. Finally, set the ciphertext as the IV for the next iteration
                Array.Copy(blocks[i] = blocks[i].XOR(cipher.Encrypt(currentIV_e)), currentIV_e, cipher.BlockSize);
            
            return CollectBlocks(blocks);
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            // Split ciphertext into blocks (ciphertext should ahve a length that is a multiple of cipher.BlockSize)
            byte[][] blocks = SplitBlocks(ciphertext);
            
            for (int i = 0; i < blocks.Length; ++i)
            {
                // Store unmodified copy
                byte[] before = (byte[])blocks[i].Clone();

                // Decrypt
                blocks[i] = blocks[i].XOR(cipher.Encrypt(currentIV_d));

                // Set the ciphertext a the iv for the next iteration
                Array.Copy(before, currentIV_d, cipher.BlockSize);
            }

            return CollectBlocks(blocks);
        }
    }
}
