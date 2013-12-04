using Bitnet.Client.Encoder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bitnet.Client.StackOverflow
{
    /// <summary>
    /// from user digEmAll
    ///  http://stackoverflow.com/a/5757109/328397
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class ArraySegmentWrapper : IList<byte>
    {


        /// <summary>
        /// @Mark Gavel at
        /// http://stackoverflow.com/a/713355/328397
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="a1"></param>
        /// <param name="a2"></param>
        /// <returns></returns>
        public static bool ArraysEqual<T>(T[] a1, T[] a2)
        {
            if (ReferenceEquals(a1, a2))
                return true;

            if (a1 == null || a2 == null)
                return false;

            if (a1.Length != a2.Length)
                return false;

            EqualityComparer<T> comparer = EqualityComparer<T>.Default;
            for (int i = 0; i < a1.Length; i++)
            {
                if (!comparer.Equals(a1[i], a2[i])) return false;
            }
            return true;
        }

        private readonly ArraySegment<byte> segment;

        public ArraySegmentWrapper(ArraySegment<byte> segment)
        {
            this.segment = segment;
        }

        public ArraySegmentWrapper(byte[] array, int offset, int count)
            : this(new ArraySegment<byte>(array, offset, count))
        {
        }

        public int IndexOf(byte item)
        {
            for (int i = segment.Offset; i < segment.Offset + segment.Count; i++)
                if (Equals(segment.Array[i], item))
                    return i;
            return -1;
        }

        public void Insert(int index, byte item)
        {
            throw new NotSupportedException();
        }

        public void RemoveAt(int index)
        {
            throw new NotSupportedException();
        }

        public byte this[int index]
        {
            get
            {
                if (index >= this.Count)
                    throw new IndexOutOfRangeException();
                return this.segment.Array[index + this.segment.Offset];
            }
            set
            {
                if (index >= this.Count)
                    throw new IndexOutOfRangeException();
                this.segment.Array[index + this.segment.Offset] = value;
            }
        }

        public void Add(byte item)
        {
            throw new NotSupportedException();
        }

        public void Clear()
        {
            throw new NotSupportedException();
        }

        public bool Contains(byte item)
        {
            return this.IndexOf(item) != -1;
        }

        public void CopyTo(byte[] array, int arrayIndex)
        {
            for (int i = segment.Offset; i < segment.Offset + segment.Count; i++)
            {
                array[arrayIndex] = segment.Array[i];
                arrayIndex++;
            }
        }

        public int Count
        {
            get { return this.segment.Count; }
        }

        public bool IsReadOnly
        {
            get { return false; }
        }

        public bool Remove(byte item)
        {
            throw new NotSupportedException();
        }

        public IEnumerator<byte> GetEnumerator()
        {
            for (int i = segment.Offset; i < segment.Offset + segment.Count; i++)
                yield return segment.Array[i];
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public Stream ToStream(int startBytes, int maxBytes)
        {
            MemoryStream stream = new MemoryStream((byte[])this.segment.Array, startBytes, maxBytes, false, true);
            return stream;
        }

        public string ToHex(int startingByte, int maxbits)
        {
            return HexEncoderSO.ByteArrayToHexViaByteManipulation(this.segment.Array, startingByte, maxbits);
        }



    }
}
