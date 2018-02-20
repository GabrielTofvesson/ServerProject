using System.Collections.Generic;

namespace Tofvesson.Crypto
{

    /*
     * -----------------------------------------------
     * WARNING WARNING WARNING WARNING WARNING WARNING
     * -----------------------------------------------
     * 
     * If you are looking for useful code that is feasibly usable in the application of RSA, you are in the wrong place!
     * This code is not intended to be executed (despite the stability and functionality). The code featured below is
     * created with the sole purpose of modelling a C++ representation in a higher language (for simplicity).
     * 
     * Note: The below model is no longer of any use, as the idea, that this model was to represent a part, of has been scrapped.
     * 
     * 
     * 
     * Proof-of-concept for a simplified BigInteger to be implemented in C++ in an OpenCL kernel.
     * This has been opted agains due to the concerns regarding varying hardware implementations what this program should be applicable on.
     * The implementation would almost surely have been modified to be classless in the OpenCL implementation, but would otherwise follow the model below fairly strictly.
     */
    class Integer
    {
        // Some nice constants
        public static readonly Integer ONE = new Integer(1);
        public static readonly Integer ZERO = new Integer();
        public static readonly Integer MINUS_ONE = new Integer(-1);


        private List<byte> val = new List<byte>();
        
        public bool IsNegative { get; private set; }

        public Integer() { }
        public Integer(int value)
        {
            if ((IsNegative = value < 0)) value *= -1;
            for (int i = 0; i < 4; ++i) val.Add((byte)((value >> i * 8) & 255));
            ClipZeroes();
        }
        public Integer(List<byte> l) { val.AddRange(l); }
        public Integer(Integer i) : this(i.val) { IsNegative = i.IsNegative; }

        public Integer Add(Integer other)
        {
            Integer result = new Integer(this);
            result._Add(other);
            return result;
        }

        public Integer Sub(Integer other)
        {
            Integer result = new Integer(this);
            result._Sub(other);
            return result;
        }

        // Tests equality
        public bool Equ(Integer other)
        {
            if (IsNegative != other.IsNegative || val.Count!=other.val.Count) return false;
            for (int i = 0; i < val.Count; ++i) if (val[i] != other.val[i]) return false;
            return true;
        }

        // Tests lack of equality
        public bool Neq(Integer other) => !Equ(other);

        // Checks if this is greather than the given value
        public bool Gre(Integer other) => _Cmp(other, true) == 1;

        // Performs a greater-than-or-equal-to comparison
        public bool Grq(Integer other) => _Cmp(other, true) != 0;

        // Checks if this is less than the given value
        public bool Let(Integer other) => _Cmp(other, false) == 1;

        // Performs a less-than-or-equal-to comparison
        public bool Leq(Integer other) => _Cmp(other, false) != 0;

        // Performs a numerical comparison based on the "greater than" comparison
        private int _Cmp(Integer other, bool grt)
        {
            // If the other number is less than zero and this is a positive number, this number is larger and vice versa
            if (other.IsNegative && !IsNegative && other.val.Count != 0) return grt ? 1 : 0;
            if (IsNegative && !other.IsNegative && val.Count != 0) return grt ? 0 : 1;
            long l1, l2;
            long idx = 0;
            while ((l1=GetNthSetBit(idx, false))==(l2=other.GetNthSetBit(idx, false))) {
                ++idx;
                if (l1 == -1) return 2;
            }
            return ((l1 > l2 && (!IsNegative == grt)) || ((IsNegative == grt) && l1 < l2)) ? 1 : 0;
        }

        private void _Sub(Integer other)
        {
            bool neg;
            if (other.IsNegative ^ IsNegative) // this - (-other) = this + other
            {
                neg = IsNegative;
                IsNegative = false;
                other.IsNegative = false;
                _Add(other);
                other.IsNegative = !neg;
                IsNegative = neg;
                return;
            }
            if (IsNegative) // -this - (-other) = -this + other = other - this
            {
                Integer res = new Integer(other);
                res.IsNegative = false;
                this.IsNegative = false;
                res._Sub(this);
                IsNegative = res.IsNegative;
                val = res.val;
            }
            else if (Let(other)) // this - other (where other>this)
            {
                Integer res = new Integer(other);
                res._Sub(this);
                this.IsNegative = true;
                val = res.val;
            }
            else // this - other (where other<=this)
            {
                // Get two's complement of the other value
                Integer tc = new Integer(other);
                tc.TwosComplement();
                tc._Add(this);
                long idx = tc.GetNthSetBit(0, false);
                if (idx != -1) tc.val[(int)(idx / 8L)] &= (byte) ~(1 << (int)(idx % 8));
                tc.ClipZeroes();
                val = tc.val;
            }
        }

        private void _Add(Integer other)
        {
            if (other.IsNegative != IsNegative)
            {
                if (other.IsNegative)
                {
                    other.IsNegative = false;
                    _Sub(other);
                    other.IsNegative = true;
                }
                else
                {
                    Integer tmp = new Integer(other);
                    tmp._Sub(this);
                    IsNegative = tmp.IsNegative;
                    val = tmp.val;
                }
                return;
            }
            bool carry = false;
            bool greater = other.val.Count > val.Count;
            int min = greater ? val.Count : other.val.Count;
            Integer larger = greater ? other : other.val.Count < this.val.Count ? this : null;

            for(int i = 0; i<min; ++i)
            {
                int res = val[i] + other.val[i] + (carry? 1 : 0);
                carry = res > 255;
                val[i] = (byte)(res % 256);
            }
            if (larger == other)
            {
                for(int i = min; i<larger.val.Count; ++i)
                {
                    int res = larger.val[i] + (carry ? 1 : 0);
                    carry = res < 255;
                    val.Add((byte)(res % 256));
                }
            }else
            {
                int at = min;
                while (carry)
                {
                    if (at == val.Count)
                    {
                        val.Add(1);
                        break;
                    }
                    int res = val[at] + 1;
                    carry = res == 256;
                    val[at] = (byte)(res % 256);
                    ++at;
                }
            }
            ClipZeroes();
        }

        private void TwosComplement()
        {
            for (int i = 0; i < val.Count; ++i) val[i] = (byte) ~val[i];
            _Add(new Integer(1));
        }


        public override string ToString()
        {
            string s = IsNegative && val.Count > 0 ? "-" : val.Count == 0 ? "0" : "";
            for (int i = (val.Count) * 8 - 1; i>=0; --i) s += (val[i / 8] & (1 << (i % 8))) >> (i % 8);
            return s;
        }

        private long GetNthSetBit(long index, bool minFirst)
        {
            long target = index+1;
            for(long l = minFirst?0:(val.Count*8)-1; (minFirst && l<val.Count*8) || (!minFirst && l>=0) ; l += minFirst ? 1 : -1)
            {
                if ((val[(int)(l / 8)] & (1 << (int)(l % 8))) != 0 && --target == 0) return l;
            }
            return -1;
        }

        public int FirstSetBit
        {
            get
            {
                for (int i = 0; i < val.Count * 8; ++i) if ((val[i / 8] & (1 << (i % 8))) != 0) return i;
                return -1;
            }
        }

        // Pruning methods
        private void ClipZeroes()
        {
            for (int i = val.Count - 1; i >= 0; --i)
                if (val[i] == 0) val.RemoveAt(i);
                else break;
        }
    }
}
