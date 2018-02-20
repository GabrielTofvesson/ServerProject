﻿using System;
using System.Net;
using Tofvesson.Crypto;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            byte result = AESFunctions.GF28Mod(12);
            bool connected = false;

            AES symCrypto = LoadAES();
            if (symCrypto == null)
            {
                Console.Write("Enter AES password: ");
                symCrypto = new AES(Console.ReadLine());
                Console.Write("Would you like to save the generated AES keys? (y/N): ");
                if (Console.In.ReadYNBool("y"))
                {
                    Console.Write("Enter the base file name to be used: ");
                    try
                    {
                        symCrypto.Save(Console.ReadLine(), true);
                    }
                    catch (Exception) { Console.WriteLine("An error ocurred while attempting to save keys!"); }
                }
            }

            NetClient client = new NetClient(symCrypto, ParseIP(), ParsePort(), (string message, out bool keepAlive) =>
            {
                Console.Write("Got message: "+message+"\nResponse (blank to exit): ");
                string response = Console.ReadLine();
                keepAlive = response.Length!=0;
                return keepAlive?response:null;
            }, cli =>
            {
                Console.WriteLine("Connected to server!");
                connected = true;
            });
            client.Connect();

            Console.WriteLine("Connecting...");
            while (!connected) System.Threading.Thread.Sleep(125);

            Console.Write("Message to send to server: ");
            string s = Console.ReadLine();
            if (s.Length == 0) s += '\0';
            client.Send(s);

            while (client.IsAlive) System.Threading.Thread.Sleep(250);
        }

        public static IPAddress ParseIP()
        {
            IPAddress addr = IPAddress.None;
            do
            {
                Console.Write("Enter server IP: ");
            } while (!IPAddress.TryParse(Console.ReadLine(), out addr));
            return addr;
        }

        public static short ParsePort()
        {
            short s;
            do
            {
                Console.Write("Enter server port: ");
            } while (!short.TryParse(Console.ReadLine(), out s));
            return s;
        }


        
        static AES LoadAES()
        {
            AES sym = null;
            Console.Write("Would you like to load AES keys from files? (y/N): ");
            while (Console.In.ReadYNBool("y"))
            {
                try
                {
                    Console.Write("Enter base file name: ");
                    sym = AES.Load(Console.ReadLine());
                    Console.WriteLine("Sucessfully loaded keys!");
                    break;
                }
                catch (Exception)
                {
                    Console.Write("One or more of the required key files could not be located. Would you like to retry? (y/N): ");
                }
            }
            return sym;
        }
    }
}
