using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ionic.Zlib;
using System.IO;
using GRPPacketDecoderLib;

namespace GRPPacketDecoder
{
    class Program
    {
        static void Main(string[] args)
        {
            Start:
            Console.Clear();
            Console.WriteLine("Input data or leave empty for done: ");
            string allInput = "";
            string input = "";
            Console.Write(">");
            while (!string.IsNullOrEmpty(input = Console.ReadLine()))
            {
                allInput += input;
                Console.Write(">");
            }
            if (string.IsNullOrEmpty(allInput))
            {
                Console.WriteLine("Can't have empty input!");
                Console.ReadLine();
                goto Start;
            }
            byte[] data = StringToByteArray(allInput);
            Packet packet = PacketDecoder.FromBytes(data);
            PacketDecoder.LogPacket(packet);
            Console.WriteLine("");
            //byte[] data2 = PacketDecoder.ToBytes(packet);
            //Packet packet2 = PacketDecoder.FromBytes(data2);
            //Console.WriteLine(BitConverter.ToString(data2).Replace("-", string.Empty));
            //PacketDecoder.LogPacket(packet2);
            Console.ReadLine();
            goto Start;
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2).Replace(" ", string.Empty), 16))
                             .ToArray();
        }
    }
}
