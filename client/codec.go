package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	mrand "math/rand"
)

func newCodec(key string, cfg *config) (*codec, error) {
	r := newRogerRand(key)
	blvOffset := int32(r.getrandbits(31).Int64())
	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	mapped := base
	if key != "debug" {
		chars := []byte(base)
		for i := len(chars) - 1; i > 0; i-- {
			j := int(r.randBelow(uint64(i + 1)))
			chars[i], chars[j] = chars[j], chars[i]
		}
		mapped = string(chars)
	}
	c := &codec{blvOffset: blvOffset, mappedBase64: mapped, cfg: cfg}
	for i := 0; i < 256; i++ {
		c.enc[i] = byte(i)
		c.dec[i] = byte(i)
	}
	for i := range base {
		c.enc[base[i]] = mapped[i]
		c.dec[mapped[i]] = base[i]
	}
	return c, nil
}

func (c *codec) mapBase64(data []byte) []byte {
	out := append([]byte(nil), data...)
	for i := range out {
		out[i] = c.enc[out[i]]
	}
	return out
}

func (c *codec) base64ArrayList() string {
	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	values := make([]string, 0, 128)
	for i := 0; i < 128; i++ {
		ch := byte(i)
		idx := strings.IndexByte(base, ch)
		if idx < 0 {
			values = append(values, "-1")
			continue
		}
		values = append(values, strconv.Itoa(strings.IndexByte(c.mappedBase64, ch)))
	}
	return strings.Join(values, ",")
}

func (c *codec) currentHello() []byte {
	r := newRogerRand(c.cfg.key)
	_ = r.getrandbits(31)
	if c.cfg.key != "debug" {
		for i := 63; i > 0; i-- {
			_ = r.randBelow(uint64(i + 1))
		}
	}
	_ = r.randValue("")
	return []byte("<!-- " + r.randValue("roger/"+version) + " -->")
}

func (c *codec) encodeBody(info map[string][]byte) string {
	raw := c.blvEncode(info, false)
	enc := []byte(base64.StdEncoding.EncodeToString(raw))
	for i := range enc {
		enc[i] = c.enc[enc[i]]
	}
	return string(enc)
}

func (c *codec) decodeBody(data []byte) (map[string][]byte, error) {
	mapped := bytes.TrimSpace(data)
	for i := range mapped {
		mapped[i] = c.dec[mapped[i]]
	}
	raw, err := base64.StdEncoding.DecodeString(string(mapped))
	if err != nil {
		return nil, err
	}
	return c.blvDecode(raw)
}

func (c *codec) encodeStreamFrame(info map[string][]byte) []byte {
	raw := c.blvEncode(info, true)
	enc := []byte(base64.StdEncoding.EncodeToString(raw))
	enc = bytes.TrimRight(enc, "=")
	for i := range enc {
		enc[i] = c.enc[enc[i]]
	}
	prefix := []byte(fmt.Sprintf("%08x", len(enc)))
	return append(prefix, enc...)
}

func (c *codec) readStreamFrame(r *bufio.Reader) (map[string][]byte, error) {
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, err
	}
	n64, err := strconv.ParseInt(string(prefix), 16, 32)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, int(n64))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	for i := range payload {
		payload[i] = c.dec[payload[i]]
	}
	for len(payload)%4 != 0 {
		payload = append(payload, '=')
	}
	raw, err := base64.StdEncoding.DecodeString(string(payload))
	if err != nil {
		return nil, err
	}
	return c.blvDecode(raw)
}

func (c *codec) decodeStreamFrame(payload []byte) (map[string][]byte, error) {
	mapped := append([]byte(nil), payload...)
	for i := range mapped {
		mapped[i] = c.dec[mapped[i]]
	}
	for len(mapped)%4 != 0 {
		mapped = append(mapped, '=')
	}
	raw, err := base64.StdEncoding.DecodeString(string(mapped))
	if err != nil {
		return nil, err
	}
	return c.blvDecode(raw)
}

func (c *codec) blvEncode(info map[string][]byte, compact bool) []byte {
	out := []byte{}
	if !compact {
		head := randBytes(mrand.Intn(16) + 5)
		out = appendBLV(out, 0, c.blvOffset, head)
	}
	dataCompressed := false
	keys := make([]string, 0, len(info))
	for k := range info {
		if k != "DATACOMP" {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		v := info[k]
		if len(v) == 0 || (compact && k == "DATA" && len(v) == 0) {
			continue
		}
		if k == "DATA" && shouldCompressData(c.cfg.clientCompression, v, c.cfg.clientOptimalLimit) {
			v = zlibCompress(v, compressionLevel(c.cfg.clientCompression, len(v)))
			dataCompressed = true
		}
		out = appendBLV(out, headByName[k], c.blvOffset, v)
	}
	if dataCompressed {
		out = appendBLV(out, hDataComp, c.blvOffset, []byte("1"))
	}
	if !compact {
		tail := randBytes(mrand.Intn(16) + 5)
		out = appendBLV(out, 39, c.blvOffset, tail)
	}
	return out
}

func appendBLV(out []byte, h byte, offset int32, v []byte) []byte {
	out = append(out, h)
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(v)+int(offset)))
	out = append(out, l...)
	out = append(out, v...)
	return out
}

func (c *codec) blvDecode(data []byte) (map[string][]byte, error) {
	info := map[string][]byte{}
	for i := 0; i < len(data); {
		if i+5 > len(data) {
			return nil, errors.New("short BLV item")
		}
		h := data[i]
		l := int(int32(binary.BigEndian.Uint32(data[i+1:i+5])) - c.blvOffset)
		i += 5
		if l < 0 || i+l > len(data) {
			return nil, errors.New("invalid BLV length")
		}
		v := append([]byte(nil), data[i:i+l]...)
		i += l
		if name, ok := nameByHead[h]; ok {
			info[name] = v
		}
	}
	if len(info["DATA"]) > 0 && len(info["DATACOMP"]) > 0 {
		dec, err := zlibDecompress(info["DATA"])
		if err != nil {
			return nil, err
		}
		info["DATA"] = dec
	}
	return info, nil
}

func compressionLevel(mode string, n int) int {
	if mode == "optimal" || mode == "smart" {
		return 1
	}
	if n <= 8192 {
		return 1
	}
	if n <= 65536 {
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
	dataLen := float64(len(data))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / dataLen
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func shouldCompressData(mode string, data []byte, optimalLimit int) bool {
	if len(data) <= optimalLimit {
		return false
	}
	if mode == "smart" {
		return byteEntropy(data) < 7.5
	}
	return mode == "optimal" || mode == "dynamic"
}

func zlibCompress(data []byte, level int) []byte {
	var b bytes.Buffer
	w, _ := zlib.NewWriterLevel(&b, level)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

func zlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
