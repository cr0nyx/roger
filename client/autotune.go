package main

import (
	"log"
	"strconv"
	"time"
)

const (
	autoTuneWindow     = 5 * time.Second
	autoTuneBusyBytes  = 256 * 1024
	autoTuneMinReadBuf = 1024
	autoTuneMaxReadBuf = 50 * 1024
	autoTuneMinMaxRead = 64 * 1024
	autoTuneMaxMaxRead = 1024 * 1024
)

func (s *session) autoTuneEnabled() bool {
	return s.client.cfg.autoTune && s.mark != ""
}

func (s *session) currentReadBuf() int {
	s.autoTuneMu.Lock()
	defer s.autoTuneMu.Unlock()
	if s.readBuf <= 0 {
		return s.client.cfg.readBuf
	}
	return s.readBuf
}

func (s *session) currentMaxReadSize() int {
	s.autoTuneMu.Lock()
	defer s.autoTuneMu.Unlock()
	if s.maxReadSize <= 0 {
		return s.client.cfg.maxReadSize
	}
	return s.maxReadSize
}

func (s *session) recordTune(up, down, errors int) {
	if !s.autoTuneEnabled() {
		return
	}
	s.autoTuneMu.Lock()
	s.tuneUp += up
	s.tuneDown += down
	s.tuneErrors += errors
	if up > 0 || down > 0 {
		s.tuneLastData = time.Now()
	}
	s.autoTuneMu.Unlock()
	s.maybeAutoTune()
}

func (s *session) maybeAutoTune() {
	if !s.autoTuneEnabled() {
		return
	}
	now := time.Now()
	update := map[string][]byte{}

	s.autoTuneMu.Lock()
	if s.tuneStart.IsZero() {
		s.tuneStart = now
	}
	if now.Sub(s.tuneStart) < autoTuneWindow {
		s.autoTuneMu.Unlock()
		return
	}

	readBuf := s.readBuf
	maxRead := s.maxReadSize
	if readBuf <= 0 {
		readBuf = s.client.cfg.readBuf
	}
	if maxRead <= 0 {
		maxRead = s.client.cfg.maxReadSize
	}

	newReadBuf := readBuf
	newMaxRead := maxRead
	total := s.tuneUp + s.tuneDown
	if s.tuneErrors > 0 {
		newReadBuf = maxInt(autoTuneMinReadBuf, readBuf/2)
		newMaxRead = maxInt(autoTuneMinMaxRead, maxRead/2)
	} else if total >= autoTuneBusyBytes {
		newReadBuf = minInt(autoTuneMaxReadBuf, maxInt(readBuf*2, readBuf+1024))
		newMaxRead = minInt(autoTuneMaxMaxRead, maxInt(maxRead*2, maxRead+64*1024))
	} else if total == 0 && now.Sub(s.tuneLastData) >= autoTuneWindow*2 {
		newReadBuf = maxInt(s.client.cfg.readBuf, readBuf/2)
		newMaxRead = maxInt(s.client.cfg.maxReadSize, maxRead/2)
	}

	if newReadBuf != readBuf {
		update["READBUF"] = []byte(strconv.Itoa(newReadBuf))
	}
	if newMaxRead != maxRead {
		update["MAXREADSIZE"] = []byte(strconv.Itoa(newMaxRead))
	}

	s.tuneStart = now
	s.tuneUp = 0
	s.tuneDown = 0
	s.tuneErrors = 0
	s.autoTuneMu.Unlock()

	if len(update) == 0 {
		return
	}
	update["CMD"] = []byte("UPDATE_SETTINGS")
	update["MARK"] = []byte(s.mark)
	log.Printf("[AUTO-TUNE] [%s] updating settings: %v", s.mark, update)
	rinfo, err := s.client.request(update, 0)
	if err != nil || string(rinfo["STATUS"]) != "OK" {
		if err != nil {
			log.Printf("[AUTO-TUNE] [%s] UPDATE_SETTINGS error: %v", s.mark, err)
		} else {
			log.Printf("[AUTO-TUNE] [%s] UPDATE_SETTINGS failed: %s", s.mark, rinfo["ERROR"])
		}
		return
	}

	s.autoTuneMu.Lock()
	if value, ok := update["READBUF"]; ok {
		if parsed, err := strconv.Atoi(string(value)); err == nil {
			s.readBuf = parsed
		}
	}
	if value, ok := update["MAXREADSIZE"]; ok {
		if parsed, err := strconv.Atoi(string(value)); err == nil {
			s.maxReadSize = parsed
		}
	}
	readBuf = s.readBuf
	maxRead = s.maxReadSize
	s.autoTuneMu.Unlock()
	log.Printf("[AUTO-TUNE] [%s] applied READBUF=%d MAXREADSIZE=%d", s.mark, readBuf, maxRead)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
