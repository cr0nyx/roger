package main

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const version = "1.0"

const (
	socksVersion  = 0x05
	socksNoAuth   = 0x00
	socksUserPass = 0x02
	socksNoMethod = 0xff
	socksOK       = 0x00
	socksRefused  = 0x05
)

const (
	hData          = 1
	hCmd           = 2
	hMark          = 3
	hStatus        = 4
	hError         = 5
	hIP            = 6
	hPort          = 7
	hRedirectURL   = 8
	hForceRedirect = 9
	hUDPFrag       = 10
	hDataComp      = 11
	hReadBuf       = 12
	hMaxReadSize   = 13
	hUDPFragSize   = 14
	hHalfClose     = 15
	hClientComp    = 16
	hServerComp    = 17
	hClientOptLim  = 18
	hServerOptLim  = 19
	hUDPTimeout    = 20
	hMode          = 21
	hModes         = 22
)

var headByName = map[string]byte{
	"DATA": hData, "CMD": hCmd, "MARK": hMark, "STATUS": hStatus, "ERROR": hError,
	"IP": hIP, "PORT": hPort, "REDIRECTURL": hRedirectURL, "FORCEREDIRECT": hForceRedirect,
	"UDPFRAG": hUDPFrag, "DATACOMP": hDataComp, "READBUF": hReadBuf, "MAXREADSIZE": hMaxReadSize,
	"UDPFRAGSIZE": hUDPFragSize, "HALFCLOSE": hHalfClose, "CLIENTCOMP": hClientComp,
	"SERVERCOMP": hServerComp, "CLIENTOPTLIMIT": hClientOptLim, "SERVEROPTLIMIT": hServerOptLim,
	"UDPTIMEOUT": hUDPTimeout, "MODE": hMode, "MODES": hModes,
}

var nameByHead = map[byte]string{}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

type countFlag int

func (c *countFlag) String() string   { return strconv.Itoa(int(*c)) }
func (c *countFlag) IsBoolFlag() bool { return true }
func (c *countFlag) Set(string) error {
	(*c)++
	return nil
}

type config struct {
	key                string
	urls               []string
	headers            []string
	listen             string
	port               int
	target             string
	remote             bool
	tunName            string
	tunCIDR            string
	tunMTU             int
	skip               bool
	verbose            int
	localDNS           bool
	readBuf            int
	maxReadSize        int
	udpFragSize        int
	udpMaxSize         int
	udpTimeout         int
	mode               string
	halfClose          bool
	asyncConnect       bool
	phpConnectTimeout  time.Duration
	clientCompression  string
	serverCompression  string
	clientOptimalLimit int
	serverOptimalLimit int
	blacklist          []string
	httpVersion        string
	autoTune           bool
	configPath         string
	ntlmAuth           string
	ntlmUser           string
	ntlmPassword       string
	socksUser          string
	socksHash          string
	proxy              string
	cookie             string
	forceRedirect      bool
	redirectURLs       []string
	requestTemplate    string
	phpSkipCookie      bool
	goServer           bool
	readInterval       time.Duration
	writeInterval      time.Duration
	maxThreads         int
	maxRetry           int
	cutLeft            int
	cutRight           int
	extract            string
}

type generateConfig struct {
	key             string
	outDir          string
	camouflageFile  string
	httpCode        int
	requestTemplate string
	readBuf         int
	maxReadSize     int
	udpFragSize     int
	udpMaxSize      int
}

type codec struct {
	blvOffset    int32
	mappedBase64 string
	enc          [256]byte
	dec          [256]byte
	cfg          *config
}

type client struct {
	cfg        *config
	codec      *codec
	httpClient *http.Client
	headers    http.Header
	serverVer  string
}

type session struct {
	client *client
	local  net.Conn
	cmd    string
	mark   string
	target string
	port   int

	closed       chan struct{}
	closeOnce    sync.Once
	halfMu       sync.Mutex
	localEOF     bool
	remoteEOF    bool
	udpConn      *net.UDPConn
	udpClient    *net.UDPAddr
	udpReasm     map[uint32]*udpReasmEntry
	lastUDPUse   time.Time
	activeMode   string
	readBuf      int
	maxReadSize  int
	autoTuneMu   sync.Mutex
	tuneStart    time.Time
	tuneUp       int
	tuneDown     int
	tuneErrors   int
	tuneLastData time.Time
	requestCount int
	replyCount   int
}

type udpReasmEntry struct {
	count int
	total uint32
	parts map[uint16][]byte
}

func init() {
	for k, v := range headByName {
		nameByHead[v] = k
	}
}
