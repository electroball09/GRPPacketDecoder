using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Linq;
using Ionic.Zlib;

namespace GRPPacketDecoderLib
{

    public class RC4
    {
        public static byte[] Encrypt(byte[] pwd, byte[] data)
        {
            int a, i, j, k, tmp;
            int[] key, box;
            byte[] cipher;

            key = new int[256];
            box = new int[256];
            cipher = new byte[data.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = pwd[i % pwd.Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++)
            {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < data.Length; i++)
            {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (byte)(data[i] ^ k);
            }
            return cipher;
        }

        public static byte[] Decrypt(byte[] pwd, byte[] data)
        {
            return Encrypt(pwd, data);
        }
    }

    public class PacketDecoder
    {
        public static readonly byte[] CryptKey = { 67, 68, 38, 77, 76 }; //CD&ML
        public const int CHECKSUM_SIZE = 4;
        public const string CHECKSUM_KEY = "cH0on9AsIXx7";

        public static Packet FromBytes(byte[] datas)
        {
            Packet packet = default(Packet);

            packet.RawData = datas;

            packet.Source = datas[0];
            packet.Destination = datas[1];
            packet.TypeFlags = datas[2];
            packet.SessionID = datas[3];
            packet.PacketSignature = new byte[4];
            Array.Copy(datas, 4, packet.PacketSignature, 0, 4);
            packet.SequenceID = BitConverter.ToUInt16(datas, 8);

            //position in the packet after the above data, since packet specific data is variable
            int position = 10;
            int specialDataSize = 0;
            if (packet.IsType(PacketType.TYPE_CONNECT) || packet.IsType(PacketType.TYPE_SYN))
            {
                specialDataSize += 4;
            }
            else if (packet.IsType(PacketType.TYPE_DATA))
            {
                specialDataSize += 1;
            }
            if (packet.HasFlag(PacketFlags.FLAG_HAS_SIZE))
            {
                specialDataSize += 2;
            }

            packet.SpecialData = new byte[specialDataSize];
            Array.Copy(datas, position, packet.SpecialData, 0, specialDataSize);
            position += specialDataSize;

            int payloadSize = datas.Length - position - CHECKSUM_SIZE;
            packet.Payload = new byte[datas.Length - position - CHECKSUM_SIZE];
            if (packet.Payload.Length > 0)
            {
                Array.Copy(datas, position, packet.Payload, 0, packet.Payload.Length);
            }

            packet.Checksum = new byte[CHECKSUM_SIZE];
            Array.Copy(datas, datas.Length - 4, packet.Checksum, 0, 4);

            return packet;
        }

        public static byte[] ToBytes(Packet packet)
        {
            int size = 10 + packet.SpecialData.Length + packet.Payload.Length + 4;
            byte[] buffer = new byte[size];

            buffer[0] = packet.Source;
            buffer[1] = packet.Destination;
            buffer[2] = packet.TypeFlags;
            buffer[3] = packet.SessionID;
            Array.Copy(packet.PacketSignature, 0, buffer, 4, 4);
            Array.ConstrainedCopy(BitConverter.GetBytes(packet.SequenceID), 0, buffer, 8, 2);
            int pos = 10;
            Array.Copy(packet.SpecialData, 0, buffer, pos, packet.SpecialData.Length);
            pos += packet.SpecialData.Length;
            Array.Copy(packet.Payload, 0, buffer, pos, packet.Payload.Length);
            pos += packet.Payload.Length;
            Array.Copy(packet.Checksum, 0, buffer, pos, 4);

            return buffer;
        }

        public static void LogPacket(Packet packet)
        {
            Console.WriteLine("     Source: {0:X2}", packet.Source);
            Console.WriteLine("Destination: {0:X2}", packet.Destination);
            Console.WriteLine("       Type: {0}", (PacketType)(packet.TypeFlags & 7));
            Console.WriteLine("      Flags: {0}", (PacketFlags)(packet.TypeFlags & 248));
            Console.WriteLine("  SessionID: {0:X2}", packet.SessionID);
            Console.WriteLine("  PacketSig: {0}", BitConverter.ToString(packet.PacketSignature).Replace("-", string.Empty));
            Console.WriteLine(" SequenceID: {0}", packet.SequenceID.ToString());
            Console.WriteLine("SpecialData: {0}", BitConverter.ToString(packet.SpecialData).Replace("-", string.Empty));
            if (packet.IsType(PacketType.TYPE_CONNECT) || packet.IsType(PacketType.TYPE_SYN))
                Console.WriteLine("    ConnSig: {0}", packet.ConnectionSignature.ToString());
            if (packet.IsType(PacketType.TYPE_DATA))
                Console.WriteLine(" FragmentID: {0}", packet.FragmentID.ToString());
            if (packet.HasFlag(PacketFlags.FLAG_HAS_SIZE))
                Console.WriteLine("PayloadSize: {0}", packet.PayloadSize);
            Console.WriteLine("    Payload: {0}", BitConverter.ToString(packet.Payload).Replace("-", string.Empty));
            if (packet.PayloadSize >= 128 && !packet.HasFlag(PacketFlags.FLAG_RELIABLE))
            {
                Console.Write(" Decompress: ");
                using (MemoryStream ms = new MemoryStream(packet.Payload))
                using (ZlibStream zs = new ZlibStream(ms, CompressionMode.Decompress))
                {
                    try
                    {
                        Console.Write("{0:X2}-", (byte)ms.ReadByte());
                        byte[] buf = new byte[packet.PayloadSize];
                        zs.Read(buf, 0, packet.PayloadSize);
                        Console.WriteLine(BitConverter.ToString(buf).Replace("-", string.Empty));
                        //Console.WriteLine(Encoding.ASCII.GetString(buf));
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                    }
                }
            }
            //if (packet.HasFlag(PacketFlags.FLAG_RELIABLE))
            //{
            //    byte[] decrypted = RC4.Decrypt(CryptKey, packet.Payload);
            //    Console.WriteLine("    Decrypt: {0}", BitConverter.ToString(decrypted).Replace("-", string.Empty));
            //}
            Console.WriteLine(" PayloadLen: {0}", packet.Payload.Length.ToString());
            Console.WriteLine("   Checksum: {0}", BitConverter.ToString(packet.Checksum).Replace("-", string.Empty));

            //byte[] dataWithoutChkSum = new byte[packet.RawData.Length - 4];
            //int chkSum = V0_CalcChecksum_32bit(dataWithoutChkSum, "cH0on9AsIXx7");
            //Console.WriteLine(" CalcChkSum: {0}", BitConverter.ToString(BitConverter.GetBytes(chkSum)).Replace("-", string.Empty));
        }

        public static byte V0_CalcChecksum(byte[] Data, string AccessKey)
        {
            int[] Buf = new int[Data.Length >> 2];
            Buffer.BlockCopy(Data, 0, Buf, 0, Buf.Length << 2);
            byte[] Sum = new byte[4];
            Buffer.BlockCopy(new int[] { Buf.Sum() }, 0, Sum, 0, 4);
            int Checksum = (byte)Encoding.ASCII.GetBytes(AccessKey).Sum(b => b);
            if ((Data.Length & 3) != 0)
                Checksum += Data.Skip(Data.Length & ~3).Sum(b => b);
            return (byte)(Checksum + Sum.Sum(b => b));
        }

        public static int V0_CalcChecksum_32bit(byte[] Data, string AccessKey)
        {
            int[] Buf = new int[Data.Length >> 2];
            Buffer.BlockCopy(Data, 0, Buf, 0, Buf.Length << 2);
            byte[] Sum = new byte[4];
            Buffer.BlockCopy(new int[] { Buf.Sum() }, 0, Sum, 0, 4);
            int Checksum = (byte)Encoding.ASCII.GetBytes(AccessKey).Sum(b => b);
            if ((Data.Length & 3) != 0)
                Checksum += Data.Skip(Data.Length & ~3).Sum(b => b);
            return (Checksum + Sum.Sum(b => b));
        }
    }

    public struct Packet
    {
        public byte[] RawData;

        public byte Source;
        public byte Destination;
        public byte TypeFlags;
        public byte SessionID;
        public byte[] PacketSignature;
        public ushort SequenceID;
        public byte[] SpecialData;
        public byte[] Payload;
        public byte[] Checksum;

        public int ConnectionSignature
        {
            get
            {
                if ((TypeFlags & 7) != (byte)PacketType.TYPE_SYN &&
                    (TypeFlags & 7) != (byte)PacketType.TYPE_CONNECT)
                {
                    return 0;
                }

                return BitConverter.ToInt32(SpecialData, 0);
            }
            set
            {
                if ((TypeFlags & 7) != (byte)PacketType.TYPE_SYN &&
                    (TypeFlags & 7) != (byte)PacketType.TYPE_CONNECT)
                {
                    return;
                }

                byte[] bytes = BitConverter.GetBytes(value);
                Array.Copy(bytes, 0, SpecialData, 0, 4);
            }
        }

        public byte FragmentID
        {
            get
            {
                if ((TypeFlags & 7) != (byte)PacketType.TYPE_DATA)
                    return 0;

                return SpecialData[0];
            }
            set
            {
                if ((TypeFlags & 7) != (byte)PacketType.TYPE_DATA)
                    return;

                SpecialData[0] = value;
            }
        }

        public ushort PayloadSize
        {
            get
            {
                if ((TypeFlags & (byte)PacketFlags.FLAG_HAS_SIZE) == 0)
                    return 0;

                return BitConverter.ToUInt16(SpecialData, SpecialData.Length - 2);
            }
            set
            {
                if ((TypeFlags & (byte)PacketFlags.FLAG_HAS_SIZE) == 0)
                    return;

                byte[] bytes = BitConverter.GetBytes(value);
                Array.Copy(bytes, 0, SpecialData, SpecialData.Length - 2, 2);
            }
        }

        public bool IsType(PacketType type)
        {
            return (TypeFlags & 7) == (byte)type;
        }

        public bool HasFlag(PacketFlags flag)
        {
            return (TypeFlags & (byte)flag) != 0;
        }
    }

    public enum PacketType : byte
    {
        TYPE_SYN        = 0b00000000,
        TYPE_CONNECT    = 0b00000001,
        TYPE_DATA       = 0b00000010,
        TYPE_DISCONNECT = 0b00000011,
        TYPE_PING       = 0b00000100,
        TYPE_UNK_01     = 0b00000101,
        TYPE_UNK_02     = 0b00000110,
        TYPE_UNK_03     = 0b00000111,
    }

    [Flags]
    public enum PacketFlags : byte
    {
        FLAG_ACK        = 0b00001000,
        FLAG_RELIABLE   = 0b00010000,
        FLAG_NEED_ACK   = 0b00100000,
        FLAG_HAS_SIZE   = 0b01000000,
        FLAG_MULTI_ACK  = 0b10000000, //maybe
    }
}
