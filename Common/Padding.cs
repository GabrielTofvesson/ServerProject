using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace Tofvesson.Crypto
{
    public interface CryptoPadding
    {
        byte[] Pad(byte[] message);
        byte[] Unpad(byte[] message);
        PaddingIdentifier GetParameters();
    }

    public sealed class PaddingIdentifier
    {
        private readonly Dictionary<string, Tuple<ParameterTypes, string>> attributes = new Dictionary<string, Tuple<ParameterTypes, string>>();
        private readonly Dictionary<string, PaddingIdentifier> nests = new Dictionary<string, PaddingIdentifier>();

        public string Name { get; private set; }

        public List<string> AttributeKeys
        {
            get
            {
                List<string> keys = new List<string>();
                keys.AddRange(attributes.Keys);
                return keys;
            }
        }

        public List<string> NestedKeys
        {
            get
            {
                List<string> keys = new List<string>();
                keys.AddRange(nests.Keys);
                return keys;
            }
        }

        public PaddingIdentifier(string name) { this.Name = name; }
        public void AddAttribute(string attr, byte[] data) => attributes.Add(attr, new Tuple<ParameterTypes, string>(ParameterTypes.BYTES, Support.ArrayToString(data)));
        public void AddAttribute(string attr, int data) => attributes.Add(attr, new Tuple<ParameterTypes, string>(ParameterTypes.NUMBER, data.ToString()));
        public void AddAttribute(string attr, PaddingIdentifier data) => nests.Add(attr, data);

        public Tuple<ParameterTypes, string> GetAttribute(string key)
        {
            if (attributes.ContainsKey(key)) return attributes[key];
            return null;
        }

        public PaddingIdentifier GetNested(string key)
        {
            if (nests.ContainsKey(key)) return nests[key];
            return null;
        }

        public XmlElement Compile(XmlDocument writeTo)
        {
            XmlElement root = writeTo.CreateElement(Name);
            foreach (string key in attributes.Keys)
            {
                XmlElement attr = writeTo.CreateElement(key);
                attr.SetAttribute("type", attributes[key].Item1.ToString());
                attr.InnerText = attributes[key].Item2;
                root.AppendChild(attr);
            }

            foreach (string key in nests.Keys) root.AppendChild(nests[key].Compile(writeTo));
            return root;
        }
    }

    public enum ParameterTypes { NUMBER, BYTES, NESTED }

    public sealed class RandomLengthPadding : CryptoPadding
    {
        private const ushort DEFAULT_MAX = 12;

        private readonly RandomProvider provider;
        private readonly byte[] delimiter;
        private readonly ushort maxLen;

        public RandomLengthPadding(RandomProvider provider, byte[] delimiter, ushort maxLen = DEFAULT_MAX)
        {
            this.provider = provider;
            this.delimiter = delimiter;
            this.maxLen = maxLen;
        }

        public RandomLengthPadding(byte[] delimiter, ushort maxLen = DEFAULT_MAX)
            : this(new RegularRandomProvider(), delimiter, maxLen)
        { }


        public byte[] Pad(byte[] message)
        {
            // Generate padding
            byte[] prepadding = GenerateSequence();
            byte[] postpadding = GenerateSequence();

            // Allocate output array
            byte[] result = new byte[message.Length + prepadding.Length + postpadding.Length + delimiter.Length * 2];

            // Assemble padding
            int index = 0;
            Array.Copy(prepadding, 0, result, 0, -(index - (index += prepadding.Length)));
            Array.Copy(delimiter, 0, result, index, -(index - (index += delimiter.Length)));
            Array.Copy(message, 0, result, index, -(index - (index += message.Length)));
            Array.Copy(delimiter, 0, result, index, -(index - (index += delimiter.Length)));
            Array.Copy(postpadding, 0, result, index, -(index - (index += postpadding.Length)));

            return result;
        }

        public byte[] Unpad(byte[] message)
        {
            int index = Support.ArrayContains(message, delimiter);
            if (index == -1) throw new InvalidPaddingException("Preceding delimiter could not be found");
            byte[] result_stage1 = new byte[message.Length - 1 - index];
            Array.Copy(message, index + 1, result_stage1, 0, message.Length - 1 - index);
            index = Support.ArrayContains(result_stage1, delimiter, false);
            if (index == -1) throw new InvalidPaddingException("Trailing delimeter could not be found");
            byte[] result_stage2 = new byte[index];
            Array.Copy(result_stage1, 0, result_stage2, 0, index);
            return result_stage2;
        }

        private byte[] GenerateSequence()
        {
            // Generate between 0 and maxLen random bytes to be used as padding
            byte[] padding = provider.GetBytes(provider.NextUShort((ushort)(maxLen + 1)));

            // Remove instances of the delimiter sequence from the padding
            int idx;
            while ((idx = Support.ArrayContains(padding, delimiter)) != -1)
                foreach (byte val in provider.GetBytes(delimiter.Length))
                    padding[idx++] = val;
            return padding;
        }

        public PaddingIdentifier GetParameters()
        {
            PaddingIdentifier id = new PaddingIdentifier("R");
            id.AddAttribute("delimiter", delimiter);
            id.AddAttribute("maxLen", maxLen);
            return id;
        }
    }

    public sealed class IncrementalPadding : CryptoPadding
    {
        private const int DEFAULT_INCREMENT = 12;

        private readonly RandomProvider provider;
        private readonly int increments;
        private readonly int determiner;


        public IncrementalPadding(RandomProvider provider, int determiner, int increments = DEFAULT_INCREMENT)
        {
            this.provider = provider;
            this.increments = increments * determiner;
            this.determiner = determiner;
            if (increments < 0) throw new InvalidPaddingException("Increments cannot be negative!");
            if (determiner <= 1) throw new InvalidPaddingException("Determiner must be a positive value larger than 1!");
            if (increments * determiner < 0) throw new InvalidPaddingException("Increment-Delimiter pair is too large!");
        }

        public byte[] Pad(byte[] message)
        {
            if (message.Length % determiner != 0)
            {
                byte[] result = new byte[message.Length + increments];
                Array.Copy(message, result, message.Length);
                Array.Copy(provider.GetBytes(increments), 0, result, message.Length, increments);
                return result;
            }
            else return message;
        }

        public byte[] Unpad(byte[] message)
        {
            if (message.Length % determiner == 0) return message;
            byte[] result = new byte[message.Length - increments];
            Array.Copy(message, result, result.Length);
            return result;
        }

        public PaddingIdentifier GetParameters()
        {
            PaddingIdentifier id = new PaddingIdentifier("I");
            id.AddAttribute("increments", increments / determiner);
            id.AddAttribute("determiner", determiner);
            return id;
        }
    }

    public sealed class SequentialPadding : CryptoPadding
    {
        private readonly List<CryptoPadding> pads = new List<CryptoPadding>();

        public SequentialPadding WithPadding(CryptoPadding padding)
        {
            pads.Add(padding);
            return this;
        }

        public byte[] Pad(byte[] message)
        {
            for (int i = 0; i < pads.Count; ++i) message = pads[i].Pad(message);
            return message;
        }

        public byte[] Unpad(byte[] message)
        {
            for (int i = pads.Count - 1; i >= 0; --i) message = pads[i].Unpad(message);
            return message;
        }

        public PaddingIdentifier GetParameters()
        {
            PaddingIdentifier id = new PaddingIdentifier("S");
            for (int i = 0; i < pads.Count; ++i) id.AddAttribute(i.ToString(), pads[i].GetParameters());
            return id;
        }
    }

    public sealed class PassthroughPadding : CryptoPadding
    {
        public byte[] Pad(byte[] message) => message;
        public byte[] Unpad(byte[] message) => message;
        public PaddingIdentifier GetParameters() => new PaddingIdentifier("P");
    }

    public static class PaddingSupport
    {
        private static readonly Regex byteFinder = new Regex("(\\d{0,3})[,\\]]");


        public static string SerializePadding(CryptoPadding padding)
        {
            XmlDocument doc = new XmlDocument();
            doc.AppendChild(padding.GetParameters().Compile(doc));

            string output;
            using (var stream = new MemoryStream())
            {
                XmlTextWriter writer = new XmlTextWriter(stream, Encoding.UTF8);
                doc.WriteTo(writer);
                writer.Flush();
                stream.Position = 0;
                using (var reader = new StreamReader(stream))
                {
                    output = reader.ReadToEnd();
                }
            }
            return output;
        }

        // WIP
        public static string NetSerialize(CryptoPadding padding) => NetSerialize(padding.GetParameters(), new StringBuilder()).ToString();
        public static string NetSerialize(PaddingIdentifier padding) => NetSerialize(padding, new StringBuilder()).ToString();
        public static StringBuilder NetSerialize(PaddingIdentifier id, StringBuilder builder)
        {
            builder.Append(id.Name).Append('{');
            foreach (string key in id.AttributeKeys) builder.Append(id.GetAttribute(key).Item2).Append(',');
            foreach (string key in id.NestedKeys) NetSerialize(id.GetNested(key), builder).Append(',');
            if (id.AttributeKeys.Count > 0 || id.NestedKeys.Count > 0) builder.Remove(builder.Length - 1, 1); // Remove last ','
            builder.Append('}');
            return builder;
        }

        // Works but is really large
        public static CryptoPadding DeserializePadding(string ser) => DeserializePadding(ser, new DummyRandomProvider());
        public static CryptoPadding DeserializePadding(string ser, RandomProvider provider)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(ser);
            XmlNodeList lst = doc.ChildNodes;
            if (lst.Count != 1) throw new XMLCryptoParseException("Cannot have more than one root node!");
            return ParseNode(lst.Item(0), provider);
        }


        private static CryptoPadding ParseNode(XmlNode el, RandomProvider provider)
        {
            XmlNodeList lst;
            switch (el.Name)
            {
                case "P":
                    return new PassthroughPadding();
                case "S":
                    {
                        SequentialPadding seq = new SequentialPadding();
                        if (el.HasChildNodes)
                        {
                            lst = el.ChildNodes;
                            foreach (XmlNode subNode in lst) seq.WithPadding(ParseNode(subNode, provider));
                        }
                        return seq;
                    }
                case "I":
                    {
                        if (el.HasChildNodes && (lst = el.ChildNodes).Count == 2)
                        {
                            int increments;
                            if (!TryParseNumberNode("increments", lst, out increments))
                                throw new XMLCryptoParseException("Invalid parameter supplied");
                            int determiner;
                            if (!TryParseNumberNode("determiner", lst, out determiner))
                                throw new XMLCryptoParseException("Invalid parameter supplied");
                            return new IncrementalPadding(provider, determiner, increments);
                        }
                        else throw new XMLCryptoParseException("No parameters supplied");
                    }
                case "R":
                    {
                        if (el.HasChildNodes && (lst = el.ChildNodes).Count == 2)
                        {
                            byte[] delimiter = TryParseByteNode("delimiter", lst);
                            if (delimiter == null) throw new XMLCryptoParseException("Invalid parameter supplied");
                            int maxLen;
                            if (!TryParseNumberNode("maxLen", lst, out maxLen))
                                throw new XMLCryptoParseException("Invalid parameter supplied");
                            return new RandomLengthPadding(provider, delimiter, (ushort)maxLen);
                        }
                        else throw new XMLCryptoParseException("No parameters supplied");
                    }
                default:
                    throw new XMLCryptoParseException($"Unrecognized padding algorithm \"{el.Name}\"");

            }
        }

        private static bool TryParseNumberNode(string name, XmlNodeList from, out int val)
        {
            XmlNode node = Support.ContainsNamedNode(name, from);
            val = 0;
            return node != null && int.TryParse(node.InnerText, out val);
        }

        public static byte[] TryParseByteNode(string name, XmlNodeList from)
        {
            XmlNode node = Support.ContainsNamedNode(name, from);
            if (node == null) return null;
            List<byte> collect = new List<byte>();
            Match m = byteFinder.Match(node.InnerText);
            while (m.Success)
            {
                collect.Add(byte.Parse(m.Groups[1].Value));
                m = m.NextMatch();
            }
            return collect.ToArray();
        }


        public class XMLCryptoParseException : SystemException
        {
            public XMLCryptoParseException() { }
            public XMLCryptoParseException(string message) : base(message) { }
            public XMLCryptoParseException(string message, Exception innerException) : base(message, innerException) { }
        }
    }

    // Exception related to padding errors
    public class InvalidPaddingException : SystemException
    {
        public InvalidPaddingException() { }
        public InvalidPaddingException(string message) : base(message) { }
        public InvalidPaddingException(string message, Exception innerException) : base(message, innerException) { }
    }
}
