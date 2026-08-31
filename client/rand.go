package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
)

type pyRand struct {
	mt    [624]uint32
	index int
	seed  *big.Int
	vclen *big.Int
}

func newRogerRand(key string) *pyRand {
	salt := "11f271c6lm0e9ypkptad1uv6e1ut1fu0pt4xillz1w9bbs2gegbv89z9gca9d6tbk025uvgjfr331o0szln"
	keyMin := 28
	keyHash := key
	if len(key) < keyMin {
		h := md5.Sum([]byte(salt[:keyMin] + key + salt[keyMin:]))
		keyHash = hex.EncodeToString(h[:])
	}
	seedBytes := []byte(hex.EncodeToString([]byte(keyHash[:keyMin])))
	seed := new(big.Int)
	seed.SetString(string(seedBytes), 16)
	a := base36(salt[:keyMin])
	m := base36(salt[keyMin:])
	vclen := new(big.Int).Exp(seed, a, m)
	r := &pyRand{seed: seed, vclen: vclen}
	r.seedBig(seed)
	return r
}

func (r *pyRand) seedBig(n *big.Int) {
	if n.Sign() < 0 {
		n = new(big.Int).Abs(n)
	}
	words := []uint32{}
	if n.Sign() == 0 {
		words = []uint32{0}
	} else {
		tmp := new(big.Int).Set(n)
		mask := big.NewInt(0xffffffff)
		for tmp.Sign() > 0 {
			words = append(words, uint32(new(big.Int).And(tmp, mask).Uint64()))
			tmp.Rsh(tmp, 32)
		}
	}
	r.initByArray(words)
}

func (r *pyRand) initGenrand(s uint32) {
	r.mt[0] = s
	for i := 1; i < 624; i++ {
		r.mt[i] = 1812433253*(r.mt[i-1]^(r.mt[i-1]>>30)) + uint32(i)
	}
	r.index = 624
}

func (r *pyRand) initByArray(key []uint32) {
	r.initGenrand(19650218)
	i, j := 1, 0
	k := 624
	if len(key) > k {
		k = len(key)
	}
	for ; k > 0; k-- {
		r.mt[i] = (r.mt[i] ^ ((r.mt[i-1] ^ (r.mt[i-1] >> 30)) * 1664525)) + key[j] + uint32(j)
		i++
		j++
		if i >= 624 {
			r.mt[0] = r.mt[623]
			i = 1
		}
		if j >= len(key) {
			j = 0
		}
	}
	for k = 623; k > 0; k-- {
		r.mt[i] = (r.mt[i] ^ ((r.mt[i-1] ^ (r.mt[i-1] >> 30)) * 1566083941)) - uint32(i)
		i++
		if i >= 624 {
			r.mt[0] = r.mt[623]
			i = 1
		}
	}
	r.mt[0] = 0x80000000
}

func (r *pyRand) uint32() uint32 {
	const upperMask uint32 = 0x80000000
	const lowerMask uint32 = 0x7fffffff
	mag01 := [2]uint32{0, 0x9908b0df}
	if r.index >= 624 {
		for kk := 0; kk < 624-397; kk++ {
			y := (r.mt[kk] & upperMask) | (r.mt[kk+1] & lowerMask)
			r.mt[kk] = r.mt[kk+397] ^ (y >> 1) ^ mag01[y&1]
		}
		for kk := 624 - 397; kk < 623; kk++ {
			y := (r.mt[kk] & upperMask) | (r.mt[kk+1] & lowerMask)
			r.mt[kk] = r.mt[kk+(397-624)] ^ (y >> 1) ^ mag01[y&1]
		}
		y := (r.mt[623] & upperMask) | (r.mt[0] & lowerMask)
		r.mt[623] = r.mt[396] ^ (y >> 1) ^ mag01[y&1]
		r.index = 0
	}
	y := r.mt[r.index]
	r.index++
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	return y
}

func (r *pyRand) random() float64 {
	a := r.uint32() >> 5
	b := r.uint32() >> 6
	return (float64(a)*67108864.0 + float64(b)) / 9007199254740992.0
}

func (r *pyRand) getrandbits(k int) *big.Int {
	if k <= 0 {
		return big.NewInt(0)
	}
	words := (k + 31) / 32
	out := new(big.Int)
	remaining := k
	for i := 0; i < words; i++ {
		word := r.uint32()
		if remaining < 32 {
			word >>= uint(32 - remaining)
		}
		part := new(big.Int).SetUint64(uint64(word))
		part.Lsh(part, uint(32*i))
		out.Or(out, part)
		remaining -= 32
	}
	return out
}

func (r *pyRand) randBelow(n uint64) uint64 {
	k := bitsLen(n)
	for {
		v := r.getrandbits(k).Uint64()
		if v < n {
			return v
		}
	}
}

func (r *pyRand) randValue(extra string) string {
	var local *pyRand
	vclen := new(big.Int).Set(r.vclen)
	if extra != "" {
		h := md5.Sum([]byte(extra))
		extraInt := new(big.Int).SetBytes(h[:])
		seedX := new(big.Int).Xor(r.seed, extraInt)
		local = &pyRand{seed: seedX, vclen: vclen}
		local.seedBig(seedX)
		vclen.Xor(vclen, extraInt)
	} else {
		local = r
	}
	bits := int(local.random()*300) + 30
	n := local.getrandbits(bits)
	n.Lsh(n, 280)
	n.Add(n, vclen)
	return strings.TrimRight(base64.StdEncoding.EncodeToString(intToBytes(n)), "=")
}

func bitsLen(n uint64) int {
	k := 0
	for n > 0 {
		k++
		n >>= 1
	}
	if k == 0 {
		return 1
	}
	return k
}

func intToBytes(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0}
	}
	return n.Bytes()
}

func base36(s string) *big.Int {
	n := big.NewInt(0)
	base := big.NewInt(36)
	for _, ch := range s {
		var v int64
		switch {
		case ch >= '0' && ch <= '9':
			v = int64(ch - '0')
		case ch >= 'a' && ch <= 'z':
			v = int64(ch-'a') + 10
		case ch >= 'A' && ch <= 'Z':
			v = int64(ch-'A') + 10
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(v))
	}
	return n
}
