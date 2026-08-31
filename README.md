# Roger

Roger is an advanced tool for pivoting and tunneling traffic over web servers. It can expose a SOCKS5 proxy or TUN interface, and it also supports local and remote port forwarding.

> This tool is limited to safety research and teaching, and the user assumes all legal and related responsibilities caused by the use of this tool! The author does not bear any legal and related responsibilities!

## Client

Roger is released with the Go client:

```bash
./roger-go -h
```

To build it from source:

```bash
cd client
go build -mod=mod -o roger-go .
```

## Generate Templates

Generate server templates with a shared key:

```bash
./roger-go generate -k password
```

By default, generated files are written to `tunnels/`.

Useful generation options:

```bash
./roger-go generate -k password -o tunnels
./roger-go generate -k password --file 404.html
./roger-go generate -k password -T 'img=data:image/png;base64,ROGERBODY&save=ok'
```

Upload one generated template to a compatible web/runtime environment, then connect the client to that URL.

## Basic SOCKS5 Usage

Start a local SOCKS5 server:

```bash
./roger-go -k password -u https://example.com/tunnel.php
```

Default listen address is `127.0.0.1:1080`.

## Features

- Go client with SOCKS5, fixed local forwarding, remote forwarding, and TUN mode.
- Server templates for PHP, Go, JavaScript, JSP, JSPX, ASPX, and ASHX.
- Multiple transport modes: `auto`, `classic`, `half-duplex`, `full-duplex`, `h2`, and `h3`.
- TCP half-close support with `SHUT_WR` forwarding.
- CONNECT, BIND, and UDP tunnel commands.
- UDP fragmentation, reassembly, and idle timeout handling.
- DATA compression with `optimal`, `dynamic`, and `smart` modes.
- Runtime tuning for selected client-server protocol parameters.
- YAML config support with CLI options taking priority.
- Custom request templates, headers, cookies, proxy settings, and response extraction.
- SOCKS5 username/password authentication.

### Config File

You can use YAML config instead of cli arguments:

```bash
./roger-go --config config.example.yml
```

But you can use them both: cli options override config values.

The config has three sections:

- `common`: values shared by generation and connection, such as `key`, `request_template`, `max_read_size`, and `udp_frag_size`.
- `generate`: template generation only.
- `connect`: client connection only.

### Transport Modes

Roger supports these client-server transport modes:

- `auto`: default mode. The client chooses the best supported mode.
- `classic`: request/response polling style.
- `half-duplex`: classic uplink with streaming downlink.
- `full-duplex`: bidirectional stream over one HTTP/1.1 connection where supported.
- `h2`: HTTP/2 stream mode for templates/runtimes that support it.
- `h3`: HTTP/3 stream mode for templates/runtimes that support it.

Supported modes by template:

| Template | Language/runtime | classic | half-duplex | full-duplex | h2 | h3 |
| --- | --- | --- | --- | --- | --- | --- |
| `tunnel.go` | Go | yes | yes | yes | yes | yes |
| `tunnel.js` | Node.js | yes | yes | yes | yes | no |
| `tunnel.jsp` | Java/JSP | yes | yes | yes | no | no |
| `tunnel.jspx` | Java/JSPX | yes | yes | yes | no | no |
| `tunnel.php` | PHP | yes | yes | no | no | no |
| `tunnel.aspx` | C#/ASPX | yes | yes | no | no | no |
| `tunnel.ashx` | C#/ASHX | yes | yes | no | no | no |

Example:

```bash
./roger-go -k password -u https://example.com/tunnel.go --mode auto
./roger-go -k password -u https://example.com/tunnel.go --mode classic
./roger-go -k password -u https://example.com/tunnel.go --mode h2
```

### TCP Half-Close

TCP half-close is enabled with `--half-close`. In normal full-close behavior, Roger closes both directions when one side stops sending. In half-close mode, Roger forwards TCP write-side shutdowns as protocol-level `SHUT_WR` messages:

```text
local app sends FIN/EOF
  -> Roger client sends SHUT_WR
  -> server template calls shutdown(SHUT_WR) toward the remote peer
  -> remote peer may still send response data back
```

The reverse direction works the same way:

```text
remote peer sends FIN/EOF
  -> server template sends SHUT_WR
  -> Roger client shuts down the local socket write side
  -> local app can still finish sending if needed
```

A TCP tunnel is fully closed only after both write directions have been closed or the session is explicitly disconnected.

### Compression

Roger can compress DATA chunks between client and server. Compression mode on one side can be different with other.

Compression modes:

- `optimal`: low-cost deflate compression.
- `dynamic`: deflate level depends on data size.
- `smart`: compresses only when data is large enough and entropy is low enough.

Example:

```bash
./roger-go -k password -u https://example.com/tunnel.go \
  --client-compression smart \
  --server-compression dynamic
```

Compression thresholds can be tuned:

```bash
./roger-go -k password -u https://example.com/tunnel.go \
  --client-optimal-limit 1024 \
  --server-optimal-limit 1024
```

### Forwarding Modes

Local SOCKS5 server:

```bash
./roger-go -k password -u https://example.com/tunnel.php
```

Local port forwarding:

```bash
./roger-go -k password -u https://example.com/tunnel.php \
  -l 127.0.0.1 -p 9000 -t 10.0.0.5:445
```

Remote port forwarding:

```bash
./roger-go -k password -u https://example.com/tunnel.php \
  --remote -l 0.0.0.0 -p 9000 -t 127.0.0.1:8080
```

### SOCKS5 Authentication

Roger can require username/password authentication on the local SOCKS5 listener. The password is configured as an MD5 hash.

```bash
./roger-go -k password -u https://example.com/tunnel.php \
  --socks-user user \
  --socks-hash 5f4dcc3b5aa765d61d8327deb882cf99
```

This protects only the local SOCKS5 server. It does not apply to fixed local port forwarding, remote forwarding, or TUN mode.

### TUN Mode

The client can run a TUN interface and forward traffic through Roger using the built-in tun2socks integration.

```bash
./roger-go -k password -u https://example.com/tunnel.go \
  --tun roger0 \
  --tun-cidr 10.250.0.2/24 \
  --tun-mtu 1400
```

Roger does not manage routes automatically; add routes on the host side as needed.

### Runtime Tuning

Useful connection parameters:

```bash
--read-buff KB
--max-read-size KB
--udp-frag-size Bytes
--udp-max-size KB
--udp-timeout Seconds
--read-interval MS
--write-interval MS
--max-threads N
--max-retry N
```

Auto tuning can adjust selected runtime values during active sessions:

```bash
./roger-go -k password -u https://example.com/tunnel.go --auto-tune
```

### Template Notes

The Go and JavaScript templates are the best candidates for newer streaming transports. PHP and C# runtime behavior can depend heavily on the web server, buffering, and process model. If a mode is unstable in a specific runtime, use `--mode classic` as the compatibility baseline.

For PHP and Node.js deployments, `--async-connect` can help in environments where connection setup is asynchronous:

```bash
./roger-go -k password -u https://example.com/tunnel.php --async-connect
```

## References

- [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)
- [suo5](https://github.com/zema1/suo5)
- [tun2socks](https://github.com/xjasonlyu/tun2socks)