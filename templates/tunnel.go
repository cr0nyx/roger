package main

import (
    "bufio"
    "bytes"
    "compress/zlib"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "io"
    "io/ioutil"
    "math"
    "math/rand"
    "net"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/quic-go/quic-go/http3"
)

var (
    DATA          = 1
    CMD           = 2
    MARK          = 3
    STATUS        = 4
    ERROR         = 5
    IP            = 6
    PORT          = 7
    REDIRECTURL   = 8
    FORCEREDIRECT = 9
    UDPFRAG       = 10
    DATACOMP      = 11
    READBUFOPT    = 12
    MAXREADOPT    = 13
    UDPFRAGOPT    = 14
    HALFCLOSEOPT  = 15
    CLIENTCOMPOPT = 16
    SERVERCOMPOPT = 17
    CLIENTLIMITOPT = 18
    SERVERLIMITOPT = 19
    UDPTIMEOUTOPT = 20
    MODEOPT = 21
    MODES = 22


    en     = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    de     = []byte("BASE64 CHARSLIST")
    en_map = make(map[byte]byte)
    de_map = make(map[byte]byte)

    roger_hello = []byte("Roger says, 'All seems fine'")

    sessions = make(map[string]*session)
    settings = make(map[string]sessionSettings)

    lock sync.Mutex
)

type sessionSettings struct {
    readbuf int
    maxread int
    udpfrag int
    halfClose bool
    serverComp string
    serverLimit int
    udpTimeout int
    mode string
}

func defaultSettings() sessionSettings {
    return sessionSettings{
        readbuf: READBUF,
        maxread: MAXREADSIZE,
        udpfrag: UDPFRAGSIZE,
        halfClose: HALF_CLOSE_MODE,
        serverComp: "optimal",
        serverLimit: 1024,
        udpTimeout: UDP_IDLE_TIMEOUT,
        mode: "classic",
    }
}

func intSetting(info map[int][]byte, key int, fallback int) int {
    value := strings.TrimSpace(string(info[key]))
    if value == "" {
        return fallback
    }
    parsed := 0
    _, err := fmt.Sscanf(value, "%d", &parsed)
    if err != nil || parsed <= 0 {
        return fallback
    }
    return parsed
}

func boolSetting(info map[int][]byte, key int, fallback bool) bool {
    value := strings.ToLower(strings.TrimSpace(string(info[key])))
    if value == "" {
        return fallback
    }
    return value == "1" || value == "true"
}

func compressionSetting(info map[int][]byte, key int, fallback string) string {
    value := strings.ToLower(strings.TrimSpace(string(info[key])))
    if value == "dynamic" || value == "optimal" || value == "smart" {
        return value
    }
    return fallback
}

func settingsFromInfo(info map[int][]byte) sessionSettings {
    defaults := defaultSettings()
    return sessionSettings{
        readbuf: intSetting(info, READBUFOPT, defaults.readbuf),
        maxread: intSetting(info, MAXREADOPT, defaults.maxread),
        udpfrag: intSetting(info, UDPFRAGOPT, defaults.udpfrag),
        halfClose: boolSetting(info, HALFCLOSEOPT, defaults.halfClose),
        serverComp: compressionSetting(info, SERVERCOMPOPT, defaults.serverComp),
        serverLimit: intSetting(info, SERVERLIMITOPT, defaults.serverLimit),
        udpTimeout: intSetting(info, UDPTIMEOUTOPT, defaults.udpTimeout),
        mode: modeSetting(info, MODEOPT, defaults.mode),
    }
}

func modeSetting(info map[int][]byte, key int, fallback string) string {
    value := strings.ToLower(strings.TrimSpace(string(info[key])))
    if value == "classic" || value == "half" || value == "full" || value == "h2" || value == "h3" {
        return value
    }
    return fallback
}

func getSettings(mark string) sessionSettings {
    lock.Lock()
    defer lock.Unlock()
    sessSettings, ok := settings[mark]
    if ok {
        return sessSettings
    }
    return defaultSettings()
}

func setSettings(mark string, sessSettings sessionSettings) bool {
    lock.Lock()
    defer lock.Unlock()
    settings[mark] = sessSettings
    return true
}

func infoHasSettings(info map[int][]byte) bool {
    for _, key := range []int{READBUFOPT, MAXREADOPT, UDPFRAGOPT, HALFCLOSEOPT, SERVERCOMPOPT, SERVERLIMITOPT, UDPTIMEOUTOPT, MODEOPT} {
        if _, ok := info[key]; ok {
            return true
        }
    }
    return false
}

func sessionSettingsFromRequest(mark string, info map[int][]byte) sessionSettings {
    if infoHasSettings(info) {
        return settingsFromInfo(info)
    }
    return getSettings(mark)
}

func updateSettingsFromInfo(current sessionSettings, info map[int][]byte) sessionSettings {
    updated := current
    if _, ok := info[READBUFOPT]; ok {
        updated.readbuf = intSetting(info, READBUFOPT, updated.readbuf)
    }
    if _, ok := info[MAXREADOPT]; ok {
        updated.maxread = intSetting(info, MAXREADOPT, updated.maxread)
    }
    if _, ok := info[UDPFRAGOPT]; ok {
        updated.udpfrag = intSetting(info, UDPFRAGOPT, updated.udpfrag)
    }
    if _, ok := info[HALFCLOSEOPT]; ok {
        updated.halfClose = boolSetting(info, HALFCLOSEOPT, updated.halfClose)
    }
    if _, ok := info[SERVERCOMPOPT]; ok {
        updated.serverComp = compressionSetting(info, SERVERCOMPOPT, updated.serverComp)
    }
    if _, ok := info[SERVERLIMITOPT]; ok {
        updated.serverLimit = intSetting(info, SERVERLIMITOPT, updated.serverLimit)
    }
    if _, ok := info[UDPTIMEOUTOPT]; ok {
        updated.udpTimeout = intSetting(info, UDPTIMEOUTOPT, updated.udpTimeout)
    }
    if _, ok := info[MODEOPT]; ok {
        updated.mode = modeSetting(info, MODEOPT, updated.mode)
    }
    return updated
}

func updateSessionSettings(mark string, info map[int][]byte) bool {
    lock.Lock()
    defer lock.Unlock()
    if sess, ok := sessions[mark]; ok {
        sess.mu.Lock()
        sess.settings = updateSettingsFromInfo(sess.settings, info)
        sess.mu.Unlock()
        settings[mark] = sess.settings
        return true
    }
    if sessSettings, ok := settings[mark]; ok {
        settings[mark] = updateSettingsFromInfo(sessSettings, info)
        return true
    }
    return false
}

type udpReassembly struct {
    count int
    total int
    chunks map[int][]byte
}

type udpFragment struct {
    meta []byte
    data []byte
}

func udpFragmentPayload(data []byte, udpFragSize int) []udpFragment {
    if udpFragSize <= 0 {
        return nil
    }
    if len(data) <= udpFragSize {
        return []udpFragment{{meta: nil, data: data}}
    }
    count := (len(data) + udpFragSize - 1) / udpFragSize
    if count < 1 {
        count = 1
    }
    id := rand.Uint32()
    fragments := make([]udpFragment, 0, count)
    for i := 0; i < count; i++ {
        start := i * udpFragSize
        end := start + udpFragSize
        if end > len(data) {
            end = len(data)
        }
        meta := make([]byte, 12)
        binary.BigEndian.PutUint32(meta[0:4], id)
        binary.BigEndian.PutUint16(meta[4:6], uint16(i))
        binary.BigEndian.PutUint16(meta[6:8], uint16(count))
        binary.BigEndian.PutUint32(meta[8:12], uint32(len(data)))
        fragments = append(fragments, udpFragment{meta: meta, data: data[start:end]})
    }
    return fragments
}

func udpReassembleFragment(buffers map[uint32]*udpReassembly, data []byte, meta []byte) ([]byte, bool) {
    if len(meta) == 0 {
        return data, true
    }
    if len(meta) != 12 {
        return nil, false
    }
    id := binary.BigEndian.Uint32(meta[0:4])
    index := int(binary.BigEndian.Uint16(meta[4:6]))
    count := int(binary.BigEndian.Uint16(meta[6:8]))
    total := int(binary.BigEndian.Uint32(meta[8:12]))
    if count < 1 || index >= count || total > UDPMAXSIZE {
        return nil, false
    }
    entry := buffers[id]
    if entry == nil {
        entry = &udpReassembly{count: count, total: total, chunks: make(map[int][]byte)}
        buffers[id] = entry
    }
    if entry.count != count || entry.total != total {
        delete(buffers, id)
        return nil, false
    }
    chunk := make([]byte, len(data))
    copy(chunk, data)
    entry.chunks[index] = chunk
    if len(entry.chunks) != count {
        return nil, false
    }
    assembled := make([]byte, 0, total)
    for i := 0; i < count; i++ {
        assembled = append(assembled, entry.chunks[i]...)
    }
    delete(buffers, id)
    if len(assembled) != total {
        return nil, false
    }
    return assembled, true
}

func zip(tomap map[byte]byte, a []byte, b []byte) {
    size := len(a)
    for i := 0; i < size; i++ {
        tomap[a[i]] = b[i]
    }
}

func base64decode(data []byte) ([]byte, error) {
    size := len(data)
    out := make([]byte, size)
    for i := 0; i < size; i++ {
        n := de_map[data[i]]
        if n == 0 {
            out[i] = data[i]
        } else {
            out[i] = n
        }
    }
    return base64.StdEncoding.DecodeString(string(out))
}

func base64decodeCompact(data []byte) ([]byte, error) {
    size := len(data)
    out := make([]byte, size)
    for i := 0; i < size; i++ {
        n := de_map[data[i]]
        if n == 0 {
            out[i] = data[i]
        } else {
            out[i] = n
        }
    }
    for len(out)%4 != 0 {
        out = append(out, '=')
    }
    return base64.StdEncoding.DecodeString(string(out))
}

func base64encode(rawdata []byte) []byte {
    data := []byte(base64.StdEncoding.EncodeToString(rawdata))
    size := len(data)
    out := make([]byte, size)
    for i := 0; i < size; i++ {
        n := en_map[data[i]]
        if n == 0 {
            out[i] = data[i]
        } else {
            out[i] = n
        }
    }
    return out
}

func blv_decode(data []byte) map[int][]byte {
    info := make(map[int][]byte)
    in := bytes.NewReader(data)
    var b_byte byte
    var l_int32 int32

    for true {
        err := binary.Read(in, binary.BigEndian, &b_byte)
        if err != nil {
            break
        }
        binary.Read(in, binary.BigEndian, &l_int32)
        b := int(b_byte)
        l := int(l_int32) - BLV_L_OFFSET

        v := make([]byte, l)
        in.Read(v)
        info[b] = v
    }
    if data, ok := info[DATA]; ok {
        if _, compressed := info[DATACOMP]; compressed {
            if out, err := zlibDecompress(data); err == nil {
                info[DATA] = out
            }
        }
    }
    return info
}

func randbyte() []byte {
    min := 5
    max := 20
    length := rand.Intn(max-min-1) + 1
    data := make([]byte, length)
    rand.Read(data)
    return data
}

func blv_encode(info map[int][]byte, compressionMode string, optimalLimit int) []byte {
    info[0] = randbyte()
    info[39] = randbyte()

    data := bytes.NewBuffer([]byte{})
    dataCompressed := false
    for b, v := range info {
        if b == DATACOMP {
            continue
        }
        if b == DATA && shouldCompressData(compressionMode, v, optimalLimit) {
            v = zlibCompress(v, compressionLevel(compressionMode, len(v)))
            dataCompressed = true
        }
        l := len(v)
        binary.Write(data, binary.BigEndian, byte(b))
        binary.Write(data, binary.BigEndian, int32(l) + BLV_L_OFFSET)
        binary.Write(data, binary.BigEndian, v)
    }
    if dataCompressed {
        v := []byte("1")
        binary.Write(data, binary.BigEndian, byte(DATACOMP))
        binary.Write(data, binary.BigEndian, int32(len(v)) + BLV_L_OFFSET)
        binary.Write(data, binary.BigEndian, v)
    }
    return data.Bytes()
}

func blv_encode_compact(info map[int][]byte, compressionMode string, optimalLimit int) []byte {
    data := bytes.NewBuffer([]byte{})
    dataCompressed := false
    for b, v := range info {
        if b == DATACOMP || len(v) == 0 {
            continue
        }
        if b == DATA && shouldCompressData(compressionMode, v, optimalLimit) {
            v = zlibCompress(v, compressionLevel(compressionMode, len(v)))
            dataCompressed = true
        }
        binary.Write(data, binary.BigEndian, byte(b))
        binary.Write(data, binary.BigEndian, int32(len(v)) + BLV_L_OFFSET)
        binary.Write(data, binary.BigEndian, v)
    }
    if dataCompressed {
        v := []byte("1")
        binary.Write(data, binary.BigEndian, byte(DATACOMP))
        binary.Write(data, binary.BigEndian, int32(len(v)) + BLV_L_OFFSET)
        binary.Write(data, binary.BigEndian, v)
    }
    return data.Bytes()
}

func compressionLevel(mode string, dataLen int) int {
    if mode == "optimal" || mode == "smart" {
        return 1
    }
    if dataLen <= 8192 {
        return 1
    }
    if dataLen <= 65536 {
        return 3
    }
    return 6
}

func byteEntropy(data []byte) float64 {
    if len(data) == 0 {
        return 0
    }
    var counts [256]int
    for _, b := range data {
        counts[b]++
    }
    entropy := 0.0
    dataLenFloat := float64(len(data))
    for _, count := range counts {
        if count == 0 {
            continue
        }
        probability := float64(count) / dataLenFloat
        entropy -= probability * math.Log2(probability)
    }
    return entropy
}

func shouldCompressData(mode string, data []byte, optimalLimit int) bool {
    if mode == "smart" {
        if len(data) <= 1024 {
            return false
        }
        return byteEntropy(data) < 7.5
    }
    if len(data) <= optimalLimit {
        return false
    }
    return mode == "optimal" || mode == "dynamic"
}

func zlibCompress(data []byte, level int) []byte {
    var out bytes.Buffer
    writer, err := zlib.NewWriterLevel(&out, level)
    if err != nil {
        return data
    }
    _, _ = writer.Write(data)
    _ = writer.Close()
    return out.Bytes()
}

func zlibDecompress(data []byte) ([]byte, error) {
    reader, err := zlib.NewReader(bytes.NewReader(data))
    if err != nil {
        return nil, err
    }
    defer reader.Close()
    return ioutil.ReadAll(reader)
}

func newSession(conn net.Conn, tcp bool, sessSettings sessionSettings) *session {
    sess := &session{
        conn:  conn,
        buf:   new(bytes.Buffer),
        input: make(chan sessionInput, 100),
        done:  make(chan struct{}),
        tcp: tcp,
        dst: "",
        src: "",
        uOpen: false,
        udpin: make(map[uint32]*udpReassembly),
        settings: sessSettings,
        lastActivity: time.Now(),
    }

    go func() {
        for {
            buf := make([]byte, sess.settings.readbuf)
            if sess.tcp {
                n, err := sess.conn.Read(buf) 
                if err != nil {
                    if err == io.EOF {
                        sess.mu.Lock()
                        sess.remoteWriteClosed = true
                        sess.mu.Unlock()
                        return
                    }
                    sess.Close()
                    return
                }
                for {
                    sess.bufMu.Lock()
                    full := sess.buf.Len() > sess.settings.maxread
                    sess.bufMu.Unlock()
                    if !full {
                        break
                    }
                    time.Sleep(10*time.Millisecond)
                }
                sess.bufMu.Lock()
                sess.buf.Write(buf[:n])
                sess.bufMu.Unlock()
            } else {
                if time.Since(sess.LastActivity()) > time.Duration(sess.settings.udpTimeout)*time.Second {
                    sess.Close()
                    return
                }
                udpBuf := make([]byte, 65497)
                sess.conn.(*net.UDPConn).SetReadDeadline(time.Now().Add(500 * time.Millisecond))
                n, clientAddr, err := sess.conn.(*net.UDPConn).ReadFromUDP(udpBuf)
                if err != nil {
                    if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                        continue
                    }
                    sess.Close()
                    return
                }
                for {
                    sess.bufMu.Lock()
                    full := len(sess.udpbuf) > 0 && sess.buf.Len() > sess.settings.maxread
                    sess.bufMu.Unlock()
                    if !full {
                        break
                    }
                    time.Sleep(10*time.Millisecond)
                }
                sess.bufMu.Lock()
                sess.Touch()
                for _, fragment := range udpFragmentPayload(udpBuf[:n], sess.settings.udpfrag) {
                    packet := make([]byte, len(fragment.data))
                    copy(packet, fragment.data)
                    meta := make([]byte, len(fragment.meta))
                    copy(meta, fragment.meta)
                    sess.udpbuf = append(sess.udpbuf, udpPacket{data: packet, meta: meta, addr: clientAddr.String()})
                    sess.buf.Write(packet)
                }
                sess.bufMu.Unlock()
            }
        }
    }()

    go func() {
        for {
            select {
            case <-sess.done:
                return
            case input := <-sess.input:
                if sess.tcp {
                    if input.shutdownWrite {
                        sess.mu.Lock()
                        if sess.closed || sess.localWriteClosed {
                            sess.mu.Unlock()
                            continue
                        }
                        sess.localWriteClosed = true
                        sess.mu.Unlock()

                        tcpConn, ok := sess.conn.(*net.TCPConn)
                        if !ok {
                            sess.Close()
                            return
                        }
                        if err := tcpConn.CloseWrite(); err != nil {
                            sess.Close()
                            return
                        }
                        continue
                    }
                    err := writeAll(sess.conn, input.data)
                    if err != nil {
                        sess.Close()
                        return
                    }
                    continue
                }

                if !sess.uOpen {
                    continue
                }

                addr, err := net.ResolveUDPAddr("udp", input.dst)
                if err != nil {
                    sess.Close()
                    return
                }
                sess.Touch()
                packet, complete := udpReassembleFragment(sess.udpin, input.data, input.udpmeta)
                if !complete {
                    continue
                }
                _, err = sess.conn.(*net.UDPConn).WriteToUDP(packet, addr)
                if err != nil {
                    sess.Close()
                    return
                }
            }
        }
    }()
    return sess
}

type session struct {
    conn   net.Conn
    buf    *bytes.Buffer
    bufMu  sync.Mutex
    udpbuf []udpPacket
    udpin  map[uint32]*udpReassembly
    input  chan sessionInput
    done   chan struct{}
    once   sync.Once
    mu     sync.Mutex
    closed bool
    localWriteClosed bool
    remoteWriteClosed bool
    remoteWriteNotified bool
    client string
    tcp    bool
    dst    string
    src    string
    uOpen bool
    settings sessionSettings
    lastActivity time.Time
}

type sessionInput struct {
    data []byte
    udpmeta []byte
    dst string
    shutdownWrite bool
}

type udpPacket struct {
    data []byte
    meta []byte
    addr string
}

func getSession(mark string) *session {
    lock.Lock()
    defer lock.Unlock()
    return sessions[mark]
}

func setSession(mark string, sess *session) {
    lock.Lock()
    sessions[mark] = sess
    lock.Unlock()
}

func deleteSession(mark string) {
    lock.Lock()
    delete(sessions, mark)
    lock.Unlock()
}

func splitAddr(addr string) (string, string, bool) {
    host, port, err := net.SplitHostPort(addr)
    if err != nil {
        return "", "", false
    }
    return host, port, true
}

func writeAll(conn net.Conn, data []byte) error {
    for len(data) > 0 {
        n, err := conn.Write(data)
        if err != nil {
            return err
        }
        if n <= 0 {
            return fmt.Errorf("short write")
        }
        data = data[n:]
    }
    return nil
}

func (sess *session) isClosed() bool {
    sess.mu.Lock()
    defer sess.mu.Unlock()
    return sess.closed
}

func (sess *session) Touch() {
    sess.mu.Lock()
    sess.lastActivity = time.Now()
    sess.mu.Unlock()
}

func (sess *session) LastActivity() time.Time {
    sess.mu.Lock()
    defer sess.mu.Unlock()
    return sess.lastActivity
}

func (sess *session) WriteTCP(buf []byte) error {
    sess.mu.Lock()
    if sess.closed {
        sess.mu.Unlock()
        return fmt.Errorf("conn closed")
    }
    sess.mu.Unlock()

    select {
    case sess.input <- sessionInput{data: buf}:
        return nil
    case <-sess.done:
        return fmt.Errorf("conn closed")
    }
}

func (sess *session) WriteUDP(buf []byte, meta []byte, dst string) error {
    sess.mu.Lock()
    if sess.closed {
        sess.mu.Unlock()
        return fmt.Errorf("conn closed")
    }
    if !sess.uOpen {
        sess.uOpen = true
    }
    sess.mu.Unlock()

    dataCopy := make([]byte, len(buf))
    copy(dataCopy, buf)
    metaCopy := make([]byte, len(meta))
    copy(metaCopy, meta)

    select {
    case sess.input <- sessionInput{data: dataCopy, udpmeta: metaCopy, dst: dst}:
        return nil
    case <-sess.done:
        return fmt.Errorf("conn closed")
    }
}

func (sess *session) ShutdownWrite() error {
    sess.mu.Lock()
    if sess.closed {
        sess.mu.Unlock()
        return fmt.Errorf("conn closed")
    }
    if sess.localWriteClosed {
        sess.mu.Unlock()
        return nil
    }
    sess.mu.Unlock()

    if !sess.tcp {
        return fmt.Errorf("conn does not support write shutdown")
    }

    select {
    case sess.input <- sessionInput{shutdownWrite: true}:
        return nil
    case <-sess.done:
        return fmt.Errorf("conn closed")
    }
}

func (sess *session) Close() {
    sess.once.Do(func() {
        sess.mu.Lock()
        sess.closed = true
        sess.mu.Unlock()

        close(sess.done)
        sess.conn.Close()
    })
}

func writeStreamFrame(w http.ResponseWriter, sess *session, info map[int][]byte) error {
    data := blv_encode_compact(info, sess.settings.serverComp, sess.settings.serverLimit)
    encoded := base64encode(data)
    encoded = []byte(strings.TrimRight(string(encoded), "="))
    _, err := fmt.Fprintf(w, "%08x", len(encoded))
    if err != nil {
        return err
    }
    _, err = w.Write(encoded)
    if flusher, ok := w.(http.Flusher); ok {
        flusher.Flush()
    }
    return err
}

func readStreamFrame(r io.Reader) (map[int][]byte, error) {
    header := make([]byte, 8)
    if _, err := io.ReadFull(r, header); err != nil {
        return nil, err
    }
    frameLen := 0
    if _, err := fmt.Sscanf(string(header), "%08x", &frameLen); err != nil {
        return nil, err
    }
    if frameLen < 0 || frameLen > UDPMAXSIZE*2 {
        return nil, fmt.Errorf("invalid stream frame length")
    }
    payload := make([]byte, frameLen)
    if _, err := io.ReadFull(r, payload); err != nil {
        return nil, err
    }
    raw, err := base64decodeCompact(payload)
    if err != nil {
        return nil, err
    }
    return blv_decode(raw), nil
}

func applyUplinkFrame(sess *session, info map[int][]byte) error {
    cmd := string(info[CMD])
    switch cmd {
    case "HEARTBEAT":
        return nil
    case "UPDATE_SETTINGS":
        sess.mu.Lock()
        sess.settings = updateSettingsFromInfo(sess.settings, info)
        sess.mu.Unlock()
        return nil
    case "DATA":
        if sess.tcp {
            return sess.WriteTCP(info[DATA])
        }
        ip := string(info[IP])
        port := string(info[PORT])
        dst := ip + ":" + port
        sess.mu.Lock()
        sess.dst = dst
        sess.mu.Unlock()
        return sess.WriteUDP(info[DATA], info[UDPFRAG], dst)
    case "SHUT_WR":
        if !sess.settings.halfClose || !sess.tcp {
            return nil
        }
        return sess.ShutdownWrite()
    case "DISCONNECT":
        sess.Close()
        return io.EOF
    }
    return nil
}

func handleFullDuplex(w http.ResponseWriter, r *http.Request, reader io.Reader, first map[int][]byte) {
    mark := string(first[MARK])
    if string(first[CMD]) == "PROBE" {
        probeSettings := sessionSettingsFromRequest(mark, first)
        probeSession := &session{settings: probeSettings}
        rinfo := map[int][]byte{STATUS: []byte("OK")}
        if err := writeStreamFrame(w, probeSession, rinfo); err == nil {
            if flusher, ok := w.(http.Flusher); ok {
                flusher.Flush()
            }
        }
        return
    }

    sess := getSession(mark)
    if sess == nil {
        return
    }

    if flusher, ok := w.(http.Flusher); ok {
        flusher.Flush()
    }

    done := make(chan struct{})
    go func() {
        defer close(done)
        for {
            info, err := readStreamFrame(reader)
            if err != nil {
                return
            }
            if err := applyUplinkFrame(sess, info); err != nil {
                return
            }
        }
    }()

    ticker := time.NewTicker(50 * time.Millisecond)
    defer ticker.Stop()
    lastHeartbeat := time.Now()
    heartbeatInterval := 5 * time.Second
	doneCh := done
	for {
		select {
		case <-sess.done:
			return
		case <-doneCh:
			doneCh = nil
        case <-ticker.C:
            frame := map[int][]byte{STATUS: []byte("OK")}
            sent := false
            sess.bufMu.Lock()
            if sess.tcp {
                if sess.buf.Len() > 0 {
                    data := make([]byte, sess.buf.Len())
                    copy(data, sess.buf.Bytes())
                    sess.buf.Reset()
                    frame[CMD] = []byte("DATA")
                    frame[DATA] = data
                    sent = true
                }
            } else if len(sess.udpbuf) > 0 {
                packet := sess.udpbuf[0]
                sess.udpbuf = sess.udpbuf[1:]
                frame[CMD] = []byte("DATA")
                frame[DATA] = packet.data
                if len(packet.meta) > 0 {
                    frame[UDPFRAG] = packet.meta
                }
                if host, port, ok := splitAddr(packet.addr); ok {
                    frame[IP] = []byte(host)
                    frame[PORT] = []byte(port)
                }
                sent = true
            }
            sess.bufMu.Unlock()
            if !sent {
                sess.mu.Lock()
                remoteWriteClosed := sess.tcp && sess.remoteWriteClosed
                remoteWriteNotified := sess.remoteWriteNotified
                closed := sess.closed
                if remoteWriteClosed && sess.settings.halfClose && !remoteWriteNotified {
                    sess.remoteWriteNotified = true
                }
                sess.mu.Unlock()
                if remoteWriteClosed && sess.settings.halfClose && !remoteWriteNotified {
                    frame[CMD] = []byte("SHUT_WR")
                    sent = true
                } else if remoteWriteClosed && !sess.settings.halfClose || closed {
                    return
                }
            }
            if !sent {
                if time.Since(lastHeartbeat) < heartbeatInterval {
                    continue
                }
                frame[CMD] = []byte("HEARTBEAT")
                lastHeartbeat = time.Now()
            }
            if err := writeStreamFrame(w, sess, frame); err != nil {
                return
            }
        }
    }
}

func handleDownlink(w http.ResponseWriter, r *http.Request, mark string) {
    sess := getSession(mark)
    if sess == nil {
        info := map[int][]byte{STATUS: []byte("FAIL"), ERROR: []byte("Session is closed")}
        data := blv_encode(info, defaultSettings().serverComp, defaultSettings().serverLimit)
        fmt.Fprintf(w, "%s", base64encode(data))
        return
    }

    w.Header().Set("Content-Type", "application/octet-stream")
    w.Header().Set("Cache-Control", "no-store")
    w.Header().Set("Connection", "Keep-Alive")
    ticker := time.NewTicker(50 * time.Millisecond)
    defer ticker.Stop()
    lastHeartbeat := time.Now()
    heartbeatInterval := 5 * time.Second
    for {
        select {
        case <-r.Context().Done():
            return
        case <-sess.done:
            return
        case <-ticker.C:
            frame := map[int][]byte{STATUS: []byte("OK")}
            sent := false
            sess.bufMu.Lock()
            if sess.tcp {
                if sess.buf.Len() > 0 {
                    data := make([]byte, sess.buf.Len())
                    copy(data, sess.buf.Bytes())
                    sess.buf.Reset()
                    frame[CMD] = []byte("DATA")
                    frame[DATA] = data
                    sent = true
                }
            } else if len(sess.udpbuf) > 0 {
                packet := sess.udpbuf[0]
                sess.udpbuf = sess.udpbuf[1:]
                frame[CMD] = []byte("DATA")
                frame[DATA] = packet.data
                if len(packet.meta) > 0 {
                    frame[UDPFRAG] = packet.meta
                }
                if host, port, ok := splitAddr(packet.addr); ok {
                    frame[IP] = []byte(host)
                    frame[PORT] = []byte(port)
                }
                sent = true
            }
            sess.bufMu.Unlock()
            if !sent {
                sess.mu.Lock()
                remoteWriteClosed := sess.tcp && sess.remoteWriteClosed
                remoteWriteNotified := sess.remoteWriteNotified
                closed := sess.closed
                if remoteWriteClosed && sess.settings.halfClose && !remoteWriteNotified {
                    sess.remoteWriteNotified = true
                }
                sess.mu.Unlock()
                if remoteWriteClosed && sess.settings.halfClose && !remoteWriteNotified {
                    frame[CMD] = []byte("SHUT_WR")
                    sent = true
                } else if remoteWriteClosed && !sess.settings.halfClose {
                    return
                } else if closed {
                    return
                }
            }
            if !sent {
                if time.Since(lastHeartbeat) < heartbeatInterval {
                    continue
                }
                frame[CMD] = []byte("HEARTBEAT")
                lastHeartbeat = time.Now()
            }
            if err := writeStreamFrame(w, sess, frame); err != nil {
                return
            }
        }
    }
}

func roger(w http.ResponseWriter, r *http.Request) {
    defer r.Body.Close()

    reader := bufio.NewReader(r.Body)
    if header, err := reader.Peek(8); err == nil {
        frameLen := 0
        if _, err := fmt.Sscanf(string(header), "%08x", &frameLen); err == nil && frameLen >= 0 && frameLen <= UDPMAXSIZE*2 {
            if payload, err := reader.Peek(8 + frameLen); err == nil {
                raw, err := base64decodeCompact(payload[8:])
                if err == nil {
                    first := blv_decode(raw)
                    firstCmd := string(first[CMD])
                    if firstCmd == "DUPLEX" || firstCmd == "PROBE" {
                        reader.Discard(8 + frameLen)
                        handleFullDuplex(w, r, reader, first)
                        return
                    }
                }
            }
        }
    }

    w.WriteHeader(HTTPCODE)
    data, _ := ioutil.ReadAll(reader)

    if USE_REQUEST_TEMPLATE == 1 && len(data) > 0 {
        data = data[START_INDEX:]
        data = data[:len(data)-END_INDEX]
    }

    out, err := base64decode(data)
    if err == nil && len(out) != 0 {
        info := blv_decode(out)
        rinfo := make(map[int][]byte)

        cmd := string(info[CMD])
        mark := string(info[MARK])
        switch cmd {
        case "CAPS":
            rinfo[STATUS] = []byte("OK")
            rinfo[MODES] = []byte("classic,half,full,h2,h3")
        case "PROBE":
            rinfo[STATUS] = []byte("OK")
        case "SETTINGS":
            rinfo[STATUS] = []byte("OK")
        case "UPDATE_SETTINGS":
            if updateSessionSettings(mark, info) {
                rinfo[STATUS] = []byte("OK")
            } else {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte("Session is closed")
            }
        case "CONNECT":
            ip := string(info[IP])
            port_str := string(info[PORT])
            targetAddr := ip + ":" + port_str
            conn, err := net.DialTimeout("tcp", targetAddr, time.Millisecond*3000)
            if err == nil {
                setSession(mark, newSession(conn, true, sessionSettingsFromRequest(mark, info)))
                rinfo[STATUS] = []byte("OK")
            } else {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte(err.Error())
            }
        case "BIND":
            ip := string(info[IP])
            port := string(info[PORT])
            
            addr := ip + ":" + port
            l, err := net.Listen("tcp", addr)
            if err != nil {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte(err.Error())
                break
            }

            host, port, ok := splitAddr(l.Addr().String())
            if !ok {
                l.Close()
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte("Invalid bind address")
                break
            }

            rinfo[STATUS] = []byte("OK")
            rinfo[IP] = []byte(host)
            rinfo[PORT] = []byte(port)

            go func() {
                defer l.Close()
                conn, err := l.Accept()
                if err != nil {
                    return
                }
                sess := newSession(conn, true, sessionSettingsFromRequest(mark, info))
                sess.client = conn.RemoteAddr().String()
                setSession(mark, sess)
            }()
        case "UDP":
            ip := string(info[IP])
            port := string(info[PORT])
            addr, err := net.ResolveUDPAddr("udp", ip + ":" + port)
            if err != nil {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte(err.Error())
                break
            }
            conn, err := net.ListenUDP("udp", addr)
            if err == nil {
                setSession(mark, newSession(conn, false, sessionSettingsFromRequest(mark, info)))
                rinfo[STATUS] = []byte("OK")
                host, port, ok := splitAddr(conn.LocalAddr().String())
                if ok {
                    rinfo[IP] = []byte(host)
                    rinfo[PORT] = []byte(port)
                }
            } else {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte(err.Error())
            }
        case "CHECK":
            session := getSession(mark)
            
            rinfo[STATUS] = []byte("OK")
		    if session != nil {
                session.mu.Lock()
                client := session.client
                session.mu.Unlock()
                host, port, ok := splitAddr(client)
                if ok {
                    rinfo[IP] = []byte(host)
                    rinfo[PORT] = []byte(port)
                }
		    } 
        case "FORWARD":
            sess := getSession(mark)
            if sess != nil {
                data := info[DATA]
                var err error
                if sess.tcp {
                    err = sess.WriteTCP(data)
                } else {
                    ip := string(info[IP])
                    port := string(info[PORT])
                    dst := ip + ":" + port
                    sess.mu.Lock()
                    sess.dst = dst
                    sess.mu.Unlock()
                    err = sess.WriteUDP(data, info[UDPFRAG], dst)
                }
                if err == nil {
                    rinfo[STATUS] = []byte("OK")
                } else {
                    rinfo[STATUS] = []byte("FAIL")
                    rinfo[ERROR] = []byte(err.Error())
                }
            } else {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte("Session is closed")
            }

        case "READ":
            sess := getSession(mark)
            if sess != nil {
                rinfo[STATUS] = []byte("OK")
                sess.bufMu.Lock()
                hasData := false
                if sess.tcp {
                    if sess.buf.Len() > 0 {
                        data := make([]byte, sess.buf.Len())
                        copy(data, sess.buf.Bytes())
                        rinfo[DATA] = data
                        sess.buf.Reset()
                        hasData = true
                    }
                } else if len(sess.udpbuf) > 0 {
                    packet := sess.udpbuf[0]
                    sess.udpbuf = sess.udpbuf[1:]
                    rinfo[DATA] = packet.data
                    if len(packet.meta) > 0 {
                        rinfo[UDPFRAG] = packet.meta
                    }
                    host, port, ok := splitAddr(packet.addr)
                    if ok {
                        rinfo[IP] = []byte(host)
                        rinfo[PORT] = []byte(port)
                    }
                    sess.buf.Reset()
                    hasData = true
                }
                sess.bufMu.Unlock()
                if !hasData {
                    sess.mu.Lock()
                    remoteWriteClosed := sess.tcp && sess.remoteWriteClosed
                    closed := sess.closed
                    sess.mu.Unlock()
                    if remoteWriteClosed {
                        rinfo[CMD] = []byte("SHUT_WR")
                    } else if closed {
                        rinfo[STATUS] = []byte("FAIL")
                        rinfo[ERROR] = []byte("Session is closed")
                    }
                }
            } else {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte("Session is closed")
            }

        case "DOWNLINK":
            handleDownlink(w, r, mark)
            return

        case "SHUT_WR":
            sess := getSession(mark)
            if sess == nil || !sess.settings.halfClose {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte("Half-close mode is disabled")
                break
            }
            if sess != nil {
                err := sess.ShutdownWrite()
                if err == nil {
                    rinfo[STATUS] = []byte("OK")
                } else {
                    rinfo[STATUS] = []byte("FAIL")
                    rinfo[ERROR] = []byte(err.Error())
                }
            } else {
                rinfo[STATUS] = []byte("FAIL")
                rinfo[ERROR] = []byte("Session is closed")
            }

        case "DISCONNECT":
            sess := getSession(mark)
            if sess != nil {
                sess.Close()
                deleteSession(mark)
            }
            rinfo[STATUS] = []byte("OK")

        default:
            hello, _ := base64decode(roger_hello)
            fmt.Fprintf(w, "%s", hello)
            return
        }

        sessSettings := getSettings(mark)
        data := blv_encode(rinfo, sessSettings.serverComp, sessSettings.serverLimit)
        fmt.Fprintf(w, "%s", base64encode(data))
    } else {
        hello, _ := base64decode(roger_hello)
        fmt.Fprintf(w, "%s", hello)
    }

}

func main() {
    if len(os.Args) != 2 && len(os.Args) != 4 {
        return
    }
    zip(en_map, en, de)
    zip(de_map, de, en)

    listen_addr := os.Args[1]
    if !strings.ContainsAny(listen_addr, ":") {
        listen_addr = ":" + listen_addr
    }
    http.HandleFunc("/", roger)
    if len(os.Args) == 4 {
        go func() {
            _ = http3.ListenAndServeQUIC(listen_addr, os.Args[2], os.Args[3], nil)
        }()
        http.ListenAndServeTLS(listen_addr, os.Args[2], os.Args[3], nil)
    } else {
        http.ListenAndServe(listen_addr, nil)
    }
}
