(async () => {
  const path = '/proxy_path';

  const http = await import('node:http');
  const https = await import('node:https');
  const net = await import('node:net');
  const dgram = await import('node:dgram');
  const zlib = await import('node:zlib');

  const DATA = 1;
  const CMD = 2;
  const MARK = 3;
  const STATUS = 4;
  const ERROR = 5;
  const IP = 6;
  const PORT = 7;
  const REDIRECTURL = 8;
  const FORCEREDIRECT = 9;
  const UDPFRAG = 10;
  const DATACOMP = 11;
  const READBUFOPT = 12;
  const MAXREADOPT = 13;
  const UDPFRAGOPT = 14;
  const HALFCLOSEOPT = 15;
  const CLIENTCOMPOPT = 16;
  const SERVERCOMPOPT = 17;
  const CLIENTLIMITOPT = 18;
  const SERVERLIMITOPT = 19;
  const UDPTIMEOUTOPT = 20;
  const MODEOPT = 21;
  const MODES = 22;

  const en = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const de = "BASE64 CHARSLIST";

  const states = new Map();

  function blv_decode(data) {
    const info = {};
    let i = 0;
    while (i < data.length) {
      const b = data.readInt8(i);
      const l = data.readUInt32BE(i + 1) - BLV_L_OFFSET;
      i += 5;
      let v = data.slice(i, i + l);
      i += l;
      info[b] = v;
    }
    if (info[DATA] && info[DATACOMP]) {
      info[DATA] = zlib.inflateSync(info[DATA]);
    }
    return info;
  }

  function blv_encode(rinfo, compressionMode, optimalLimit) {
    rinfo[0] = randstr();
    rinfo[39] = randstr();
    const parts = [];
    let dataCompressed = false;
    for (const b in rinfo) {
      if (parseInt(b) === DATACOMP) {
        continue;
      }
      const v = rinfo[b];
      let buf_v = Buffer.isBuffer(v) ? v : Buffer.from(String(v));
      if (parseInt(b) === DATA && shouldCompressData(compressionMode, buf_v, optimalLimit)) {
        buf_v = zlib.deflateSync(buf_v, { level: compressionLevel(compressionMode, buf_v.length) });
        dataCompressed = true;
      }
      const l = buf_v.length + BLV_L_OFFSET;
      const header = Buffer.alloc(5);
      header.writeInt8(parseInt(b), 0);
      header.writeUInt32BE(l, 1);
      parts.push(header, buf_v);
    }
    if (dataCompressed) {
      const buf_v = Buffer.from('1');
      const l = buf_v.length + BLV_L_OFFSET;
      const header = Buffer.alloc(5);
      header.writeInt8(DATACOMP, 0);
      header.writeUInt32BE(l, 1);
      parts.push(header, buf_v);
    }
    return Buffer.concat(parts);
  }

  function blv_encode_compact(rinfo, compressionMode, optimalLimit) {
    const parts = [];
    let dataCompressed = false;
    for (const b in rinfo) {
      if (parseInt(b) === DATACOMP) {
        continue;
      }
      const v = rinfo[b];
      if (v === undefined || v === null || v === '') {
        continue;
      }
      let buf_v = Buffer.isBuffer(v) ? v : Buffer.from(String(v));
      if (parseInt(b) === DATA && shouldCompressData(compressionMode, buf_v, optimalLimit)) {
        buf_v = zlib.deflateSync(buf_v, { level: compressionLevel(compressionMode, buf_v.length) });
        dataCompressed = true;
      }
      const l = buf_v.length + BLV_L_OFFSET;
      const header = Buffer.alloc(5);
      header.writeInt8(parseInt(b), 0);
      header.writeUInt32BE(l, 1);
      parts.push(header, buf_v);
    }
    if (dataCompressed) {
      const buf_v = Buffer.from('1');
      const l = buf_v.length + BLV_L_OFFSET;
      const header = Buffer.alloc(5);
      header.writeInt8(DATACOMP, 0);
      header.writeUInt32BE(l, 1);
      parts.push(header, buf_v);
    }
    return Buffer.concat(parts);
  }

  function compressionLevel(mode, dataLen) {
    if (mode === 'optimal' || mode === 'smart') return 1;
    if (dataLen <= 8192) return 1;
    if (dataLen <= 65536) return 3;
    return 6;
  }

  function byteEntropy(data) {
    if (!data || data.length === 0) return 0;
    const counts = new Array(256).fill(0);
    for (const b of data) counts[b] += 1;
    let entropy = 0;
    for (const count of counts) {
      if (count === 0) continue;
      const probability = count / data.length;
      entropy -= probability * Math.log2(probability);
    }
    return entropy;
  }

  function shouldCompressData(mode, data, optimalLimit) {
    if (!data) return false;
    if (mode === 'smart') return data.length > 1024 && byteEntropy(data) < 7.5;
    if (data.length <= optimalLimit) return false;
    return mode === 'optimal' || mode === 'dynamic';
  }

  function randstr() {
    const length = Math.floor(Math.random() * 16) + 5;
    const rand = Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
      rand[i] = Math.floor(Math.random() * 256);
    }
    return rand;
  }

  function strtr(str, from, to) {
    const map = new Map();
    for (let i = 0; i < Math.min(from.length, to.length); i++) {
      map.set(from.charCodeAt(i), to.charCodeAt(i));
    }
    const buf = Buffer.from(str);
    for (let i = 0; i < buf.length; i++) {
      const rep = map.get(buf[i]);
      if (rep !== undefined) {
        buf[i] = rep;
      }
    }
    return buf.toString();
  }

  function responseSettingsFor(res) {
    if (res._rogerSettings) {
      return res._rogerSettings;
    }
    if (res._rogerMark) {
      const state = states.get(res._rogerMark);
      if (state && state.settings) {
        return state.settings;
      }
    }
    return defaultSettings();
  }

  function sendRoger(res, rinfo) {
    const sessionSettings = responseSettingsFor(res);
    const output = blv_encode(rinfo, sessionSettings.serverComp, sessionSettings.serverLimit);
    const base = output.toString('base64');
    res.end(strtr(base, en, de));
  }

  function writeStreamFrame(res, state, rinfo) {
    const output = blv_encode_compact(rinfo, state.settings.serverComp, state.settings.serverLimit);
    const base = output.toString('base64').replace(/=+$/g, '');
    const mapped = Buffer.from(strtr(base, en, de));
    res.write(Buffer.from(mapped.length.toString(16).padStart(8, '0')));
    res.write(mapped);
  }

  function decodeStreamFrame(payload) {
    const base = strtr(payload.toString(), de, en);
    const padded = base + '='.repeat((4 - (base.length % 4)) % 4);
    return blv_decode(Buffer.from(padded, 'base64'));
  }

  function sendHello(res) {
    const translated = strtr("Roger says, 'All seems fine'", de, en);
    res.end(Buffer.from(translated, 'base64').toString());
  }

  function defaultSettings() {
    return {
      readbuf: READBUF,
      maxread: MAXREADSIZE,
      udpfrag: UDPFRAGSIZE,
      halfClose: HALF_CLOSE_MODE,
      serverComp: 'optimal',
      serverLimit: 1024,
      udpTimeout: UDP_IDLE_TIMEOUT,
      mode: 'classic',
    };
  }

  function intSetting(info, key, fallback) {
    const value = info[key] ? parseInt(info[key].toString(), 10) : fallback;
    return Number.isFinite(value) && value > 0 ? value : fallback;
  }

  function boolSetting(info, key, fallback) {
    if (!info[key]) {
      return fallback;
    }
    const value = info[key].toString().toLowerCase();
    return value === '1' || value === 'true';
  }

  function compressionSetting(info, key, fallback) {
    if (!info[key]) {
      return fallback;
    }
    const value = info[key].toString().toLowerCase();
    return value === 'dynamic' || value === 'optimal' || value === 'smart' ? value : fallback;
  }

  function settingsFromInfo(info) {
    const defaults = defaultSettings();
    return {
      readbuf: intSetting(info, READBUFOPT, defaults.readbuf),
      maxread: intSetting(info, MAXREADOPT, defaults.maxread),
      udpfrag: intSetting(info, UDPFRAGOPT, defaults.udpfrag),
      halfClose: boolSetting(info, HALFCLOSEOPT, defaults.halfClose),
      serverComp: compressionSetting(info, SERVERCOMPOPT, defaults.serverComp),
      serverLimit: intSetting(info, SERVERLIMITOPT, defaults.serverLimit),
      udpTimeout: intSetting(info, UDPTIMEOUTOPT, defaults.udpTimeout),
      mode: info[MODEOPT] && ['classic', 'half', 'full', 'h2'].includes(info[MODEOPT].toString()) ? info[MODEOPT].toString() : 'classic',
    };
  }

  function updateSettingsFromInfo(current, info) {
    const updated = Object.assign({}, current);
    if (info[READBUFOPT]) {
      updated.readbuf = intSetting(info, READBUFOPT, updated.readbuf);
    }
    if (info[MAXREADOPT]) {
      updated.maxread = intSetting(info, MAXREADOPT, updated.maxread);
    }
    if (info[UDPFRAGOPT]) {
      updated.udpfrag = intSetting(info, UDPFRAGOPT, updated.udpfrag);
    }
    if (info[HALFCLOSEOPT]) {
      updated.halfClose = boolSetting(info, HALFCLOSEOPT, updated.halfClose);
    }
    if (info[SERVERCOMPOPT]) {
      updated.serverComp = compressionSetting(info, SERVERCOMPOPT, updated.serverComp);
    }
    if (info[SERVERLIMITOPT]) {
      updated.serverLimit = intSetting(info, SERVERLIMITOPT, updated.serverLimit);
    }
    if (info[UDPTIMEOUTOPT]) {
      updated.udpTimeout = intSetting(info, UDPTIMEOUTOPT, updated.udpTimeout);
    }
    if (info[MODEOPT]) {
      const mode = info[MODEOPT].toString();
      if (['classic', 'half', 'full', 'h2'].includes(mode)) {
        updated.mode = mode;
      }
    }
    return updated;
  }

  function updateSessionSettings(mark, info) {
    const state = states.get(mark);
    if (!state) {
      return false;
    }
    state.settings = updateSettingsFromInfo(state.settings, info);
    return true;
  }

  function appendReadbuf(state, data) {
    state.readbuf = Buffer.concat([state.readbuf, data]);
    if (state.readbuf.length > state.settings.maxread) {
      state.readbuf = state.readbuf.slice(state.readbuf.length - state.settings.maxread);
    }
  }

  function enqueueTcpWrite(state, data) {
    if (!state || !state.socket || !state.run || state.localWriteClosed) {
      return Promise.resolve(false);
    }
    state.writeChain = state.writeChain.then(() => new Promise(resolve => {
      if (!state.socket || !state.run || state.localWriteClosed) {
        resolve(false);
        return;
      }
      state.socket.write(data, err => {
        if (err) {
          state.run = false;
          resolve(false);
          return;
        }
        resolve(true);
      });
    }));
    return state.writeChain;
  }

  function enqueueTcpShutdownWrite(state) {
    if (!state || !state.socket || !state.run || state.localWriteClosed) {
      return Promise.resolve(false);
    }
    state.writeChain = state.writeChain.then(() => new Promise(resolve => {
      if (!state.socket || !state.run || state.localWriteClosed) {
        resolve(false);
        return;
      }
      state.localWriteClosed = true;
      state.socket.end(() => resolve(true));
    }));
    return state.writeChain;
  }

  function udpFragmentPayload(data, udpfrag) {
    if (udpfrag <= 0) {
      return [];
    }
    if (data.length <= udpfrag) {
      return [{ meta: null, data }];
    }
    const count = Math.max(1, Math.ceil(data.length / udpfrag));
    const id = Math.floor(Math.random() * 0x100000000) >>> 0;
    const fragments = [];
    for (let index = 0; index < count; index++) {
      const start = index * udpfrag;
      const chunk = data.slice(start, start + udpfrag);
      const meta = Buffer.alloc(12);
      meta.writeUInt32BE(id, 0);
      meta.writeUInt16BE(index, 4);
      meta.writeUInt16BE(count, 6);
      meta.writeUInt32BE(data.length, 8);
      fragments.push({ meta, data: chunk });
    }
    return fragments;
  }

  function udpReassembleFragment(state, data, meta) {
    if (!meta || meta.length === 0) {
      return { complete: true, data };
    }
    if (meta.length !== 12) {
      return { complete: false };
    }
    const id = meta.readUInt32BE(0);
    const index = meta.readUInt16BE(4);
    const count = meta.readUInt16BE(6);
    const total = meta.readUInt32BE(8);
    if (count < 1 || index >= count || total > UDPMAXSIZE) {
      return { complete: false };
    }
    let entry = state.udpIn.get(id);
    if (!entry) {
      entry = { count, total, chunks: new Map() };
      state.udpIn.set(id, entry);
    }
    if (entry.count !== count || entry.total !== total) {
      state.udpIn.delete(id);
      return { complete: false };
    }
    entry.chunks.set(index, data);
    if (entry.chunks.size !== count) {
      return { complete: false };
    }
    const chunks = [];
    for (let i = 0; i < count; i++) {
      if (!entry.chunks.has(i)) {
        return { complete: false };
      }
      chunks.push(entry.chunks.get(i));
    }
    state.udpIn.delete(id);
    const assembled = Buffer.concat(chunks);
    if (assembled.length !== total) {
      return { complete: false };
    }
    return { complete: true, data: assembled };
  }

  function appendUdpPacket(state, data, peer) {
    for (const fragment of udpFragmentPayload(Buffer.from(data), state.settings.udpfrag)) {
      state.udpQueue.push({ data: fragment.data, meta: fragment.meta, peer });
    }
    while (state.udpQueue.length > 0) {
      const total = state.udpQueue.reduce((size, packet) => size + packet.data.length, 0);
      if (total <= state.settings.maxread) {
        break;
      }
      state.udpQueue.shift();
    }
  }

  function hasBufferedData(state) {
    if (!state) {
      return false;
    }
    if (state.kind === 'udp') {
      return state.udpQueue.length > 0;
    }
    return state.readbuf.length > 0;
  }

  function closeState(mark, state) {
    if (!state) {
      return;
    }
    state.run = false;
    if (state.udpTimer) {
      clearInterval(state.udpTimer);
      state.udpTimer = null;
    }
    if (state.server) {
      try { state.server.close(); } catch (_) {}
    }
    if (state.socket) {
      try {
        if (state.kind === 'udp') {
          state.socket.close();
        } else {
          state.socket.destroy();
        }
      } catch (_) {}
    }
    states.delete(mark);
  }

  function touchUdpState(state) {
    state.lastActivity = Date.now();
  }

  function armUdpTimeout(mark, state) {
    if (state.udpTimer) {
      clearInterval(state.udpTimer);
    }
    state.udpTimer = setInterval(() => {
      if (!state.run) {
        closeState(mark, state);
        return;
      }
      if (Date.now() - state.lastActivity > state.settings.udpTimeout * 1000) {
        closeState(mark, state);
      }
    }, 1000);
  }

  function makeTcpState(mark, socket, client, sessionSettings) {
    const state = {
      kind: 'tcp',
      run: true,
      readbuf: Buffer.alloc(0),
      udpQueue: [],
      udpIn: new Map(),
      socket,
      server: null,
      client: client || '',
      udpPeer: null,
      writeChain: Promise.resolve(),
      localWriteClosed: false,
      remoteWriteClosed: false,
      remoteWriteNotified: false,
      settings: sessionSettings,
    };
    states.set(mark, state);
    socket.on('data', data => {
      if (state.run) {
        appendReadbuf(state, data);
      }
    });
    socket.on('end', () => {
      if (state.settings.halfClose) {
        state.remoteWriteClosed = true;
      } else {
        state.run = false;
      }
    });
    socket.on('close', () => {
      state.run = false;
    });
    socket.on('error', err => {
      console.error('tcp error:', err);
      state.run = false;
    });
    return state;
  }

  function applyUplinkFrame(mark, state, info) {
    const cmd = info[CMD] ? info[CMD].toString() : '';
    if (cmd === 'HEARTBEAT') {
      return;
    }
    if (cmd === 'UPDATE_SETTINGS') {
      if (state) {
        state.settings = updateSettingsFromInfo(state.settings, info);
      }
      return;
    }
    if (cmd === 'DISCONNECT') {
      closeState(mark, state);
      return;
    }
    if (cmd === 'SHUT_WR') {
      if (state && state.kind === 'tcp' && state.settings.halfClose && state.socket) {
        enqueueTcpShutdownWrite(state);
      }
      return;
    }
    if (cmd !== 'DATA' || !state || !state.run) {
      return;
    }
    const rawPostData = info[DATA] || Buffer.alloc(0);
    if (state.kind === 'udp') {
      const target = info[IP] ? info[IP].toString() : null;
      const port = info[PORT] ? parseInt(info[PORT].toString(), 10) : null;
      if (!target || Number.isNaN(port)) {
        return;
      }
      const packet = udpReassembleFragment(state, rawPostData, info[UDPFRAG]);
      touchUdpState(state);
      if (packet.complete) {
        state.socket.send(packet.data, port, target);
      }
    } else if (state.socket) {
      enqueueTcpWrite(state, rawPostData);
    }
  }

  function handleFullDuplex(req, res, initialBuffer = Buffer.alloc(0)) {
    let streamBuffer = initialBuffer;
    let mark = null;
    let state = null;
    let streamReady = false;
    let closed = false;
    let timer = null;
    let lastHeartbeat = Date.now();
    const heartbeatIntervalMs = 5000;

    const closeStream = () => {
      closed = true;
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    };
    res.on('close', closeStream);
    req.on('aborted', closeStream);

    const startOutput = () => {
      if (streamReady || !state) {
        return;
      }
      streamReady = true;
      res.writeHead(200);
      timer = setInterval(() => {
        if (closed) {
          return;
        }
        const current = states.get(mark);
        if (!current || (!current.run && !hasBufferedData(current) && !current.remoteWriteClosed)) {
          closeStream();
          res.end();
          return;
        }
        if (current.kind === 'udp') {
          const packet = current.udpQueue.shift();
          if (packet) {
            const frame = {};
            frame[STATUS] = 'OK';
            frame[CMD] = 'DATA';
            frame[DATA] = packet.data;
            if (packet.meta) {
              frame[UDPFRAG] = packet.meta;
            }
            frame[IP] = packet.peer.address;
            frame[PORT] = String(packet.peer.port);
            writeStreamFrame(res, current, frame);
            return;
          }
        } else {
          if (current.readbuf.length > 0) {
            const frame = {};
            frame[STATUS] = 'OK';
            frame[CMD] = 'DATA';
            frame[DATA] = current.readbuf;
            current.readbuf = Buffer.alloc(0);
            writeStreamFrame(res, current, frame);
            return;
          }
          if (current.settings.halfClose && current.remoteWriteClosed && !current.remoteWriteNotified) {
            current.remoteWriteNotified = true;
            const frame = {};
            frame[STATUS] = 'OK';
            frame[CMD] = 'SHUT_WR';
            writeStreamFrame(res, current, frame);
            return;
          }
        }
        const now = Date.now();
        if (now - lastHeartbeat < heartbeatIntervalMs) {
          return;
        }
        const heartbeat = {};
        heartbeat[STATUS] = 'OK';
        heartbeat[CMD] = 'HEARTBEAT';
        writeStreamFrame(res, current, heartbeat);
        lastHeartbeat = now;
      }, 50);
    };

    const consumeFrames = () => {
      while (streamBuffer.length >= 8) {
        const frameLen = parseInt(streamBuffer.slice(0, 8).toString(), 16);
        if (!Number.isFinite(frameLen) || frameLen < 0) {
          closeStream();
          res.end();
          return;
        }
        if (streamBuffer.length < 8 + frameLen) {
          return;
        }
        const payload = streamBuffer.slice(8, 8 + frameLen);
        streamBuffer = streamBuffer.slice(8 + frameLen);
        const info = decodeStreamFrame(payload);
        const cmd = info[CMD] ? info[CMD].toString() : '';
        if (!streamReady) {
          if ((cmd !== 'DUPLEX' && cmd !== 'PROBE') || !info[MARK]) {
            closeStream();
            res.end();
            return;
          }
          if (cmd === 'PROBE') {
            state = { settings: settingsFromInfo(info) };
            res.writeHead(200);
            const frame = {};
            frame[STATUS] = 'OK';
            writeStreamFrame(res, state, frame);
            closeStream();
            res.end();
            return;
          }
          mark = info[MARK].toString();
          state = states.get(mark);
          if (!state) {
            closeStream();
            res.end();
            return;
          }
          startOutput();
        } else {
          applyUplinkFrame(mark, state, info);
        }
      }
    };

    req.on('data', chunk => {
      streamBuffer = Buffer.concat([streamBuffer, chunk]);
      consumeFrames();
    });
    req.on('end', () => {});
    consumeFrames();
  }

  function handleClassicBody(res, body) {
      const translated = strtr(body, de, en);
      const decoded = Buffer.from(translated, 'base64');
      let info;
      try {
        info = blv_decode(decoded);
      } catch (_) {
        res.writeHead(500);
        res.end();
        return;
      }

      const rinfo = {};
      const mark = info[MARK] ? info[MARK].toString() : null;
      const cmd = info[CMD] ? info[CMD].toString() : null;
      res._rogerMark = mark;

      if (!cmd || !mark) {
        sendHello(res);
        return;
      }

      switch (cmd) {
        case 'CAPS': {
          rinfo[STATUS] = 'OK';
          rinfo[MODES] = 'classic,half,full,h2';
          sendRoger(res, rinfo);
          break;
        }

        case 'PROBE': {
          res._rogerSettings = settingsFromInfo(info);
          rinfo[STATUS] = 'OK';
          sendRoger(res, rinfo);
          break;
        }

        case 'SETTINGS': {
          rinfo[STATUS] = 'OK';
          sendRoger(res, rinfo);
          break;
        }

        case 'UPDATE_SETTINGS': {
          if (updateSessionSettings(mark, info)) {
            rinfo[STATUS] = 'OK';
          } else {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Session is closed';
          }
          sendRoger(res, rinfo);
          break;
        }

        case 'CONNECT': {
          const sessionSettings = settingsFromInfo(info);
          res._rogerSettings = sessionSettings;
          const target = info[IP] ? info[IP].toString() : null;
          const port = info[PORT] ? parseInt(info[PORT].toString(), 10) : null;
          if (!target || !port) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Missing IP or PORT';
            sendRoger(res, rinfo);
            return;
          }

          const socket = net.createConnection({ port, host: target, allowHalfOpen: sessionSettings.halfClose });
          let responded = false;
          socket.once('connect', () => {
            makeTcpState(mark, socket, '', sessionSettings);
            responded = true;
            rinfo[STATUS] = 'OK';
            sendRoger(res, rinfo);
          });
          socket.once('error', err => {
            console.error('connect error:', err);
            if (!responded) {
              responded = true;
              rinfo[STATUS] = 'FAIL';
              rinfo[ERROR] = 'Failed connecting to target';
              sendRoger(res, rinfo);
            }
          });
          break;
        }

        case 'BIND': {
          const sessionSettings = settingsFromInfo(info);
          res._rogerSettings = sessionSettings;
          const address = info[IP] ? info[IP].toString() : null;
          const port = info[PORT] ? parseInt(info[PORT].toString(), 10) : null;
          if (!address || Number.isNaN(port)) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Missing IP or PORT';
            sendRoger(res, rinfo);
            return;
          }

          const server = net.createServer({ allowHalfOpen: sessionSettings.halfClose });
          const state = {
            kind: 'bind',
            run: true,
            readbuf: Buffer.alloc(0),
            udpQueue: [],
            udpIn: new Map(),
            socket: null,
            server,
            client: '',
            udpPeer: null,
            writeChain: Promise.resolve(),
            localWriteClosed: false,
            remoteWriteClosed: false,
            settings: sessionSettings,
          };
          states.set(mark, state);
          let responded = false;

          server.once('connection', socket => {
            state.kind = 'tcp';
            state.socket = socket;
            state.client = `${socket.remoteAddress}:${socket.remotePort}`;
            server.close();
            socket.on('data', data => {
              if (state.run) {
                appendReadbuf(state, data);
              }
            });
            socket.on('end', () => {
              if (state.settings.halfClose) {
                state.remoteWriteClosed = true;
              } else {
                state.run = false;
              }
            });
            socket.on('close', () => {
              state.run = false;
            });
            socket.on('error', err => {
              console.error('bind client error:', err);
              state.run = false;
            });
          });

          server.once('error', err => {
            console.error('bind error:', err);
            state.run = false;
            if (!responded) {
              responded = true;
              states.delete(mark);
              rinfo[STATUS] = 'FAIL';
              rinfo[ERROR] = err.message;
              sendRoger(res, rinfo);
            }
          });

          server.listen(port, address, () => {
            const addr = server.address();
            responded = true;
            rinfo[STATUS] = 'OK';
            rinfo[IP] = addr.address;
            rinfo[PORT] = String(addr.port);
            sendRoger(res, rinfo);
          });
          break;
        }

        case 'UDP': {
          const sessionSettings = settingsFromInfo(info);
          res._rogerSettings = sessionSettings;
          const address = info[IP] ? info[IP].toString() : null;
          const port = info[PORT] ? parseInt(info[PORT].toString(), 10) : null;
          if (!address || Number.isNaN(port)) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Missing IP or PORT';
            sendRoger(res, rinfo);
            return;
          }

          const socket = dgram.createSocket('udp4');
          const state = {
            kind: 'udp',
            run: true,
            readbuf: Buffer.alloc(0),
            udpQueue: [],
            udpIn: new Map(),
            socket,
            server: null,
            client: '',
            udpPeer: null,
            remoteWriteClosed: false,
            settings: sessionSettings,
            lastActivity: Date.now(),
            udpTimer: null,
          };
          states.set(mark, state);
          armUdpTimeout(mark, state);
          let responded = false;

          socket.on('message', (data, peer) => {
            if (state.run) {
              touchUdpState(state);
              appendUdpPacket(state, data, peer);
            }
          });
          socket.once('error', err => {
            console.error('udp error:', err);
            state.run = false;
            try { socket.close(); } catch (_) {}
            if (!responded) {
              responded = true;
              states.delete(mark);
              rinfo[STATUS] = 'FAIL';
              rinfo[ERROR] = err.message;
              sendRoger(res, rinfo);
            }
          });
          socket.bind(port, address, () => {
            const addr = socket.address();
            responded = true;
            rinfo[STATUS] = 'OK';
            rinfo[IP] = addr.address;
            rinfo[PORT] = String(addr.port);
            sendRoger(res, rinfo);
          });
          break;
        }

        case 'CHECK': {
          const state = states.get(mark);
          rinfo[STATUS] = 'OK';
          if (state && state.client) {
            const idx = state.client.lastIndexOf(':');
            if (idx !== -1) {
              rinfo[IP] = state.client.slice(0, idx).replace(/^::ffff:/, '');
              rinfo[PORT] = state.client.slice(idx + 1);
            }
          }
          sendRoger(res, rinfo);
          break;
        }

        case 'READ': {
          const state = states.get(mark);
          if (!state || (!state.run && !hasBufferedData(state) && !state.remoteWriteClosed)) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Session is closed';
          } else {
            rinfo[STATUS] = 'OK';
            if (state.kind === 'udp') {
              const packet = state.udpQueue.shift();
              if (packet) {
                rinfo[DATA] = packet.data;
                if (packet.meta) {
                  rinfo[UDPFRAG] = packet.meta;
                }
                rinfo[IP] = packet.peer.address;
                rinfo[PORT] = String(packet.peer.port);
              }
            } else {
              rinfo[DATA] = state.readbuf;
              state.readbuf = Buffer.alloc(0);
              if (state.settings.halfClose && state.remoteWriteClosed) {
                rinfo[CMD] = 'SHUT_WR';
              }
            }
            res.setHeader('Connection', 'Keep-Alive');
          }
          sendRoger(res, rinfo);
          break;
        }

        case 'DOWNLINK': {
          const state = states.get(mark);
          if (!state || !state.run && !hasBufferedData(state) && !state.remoteWriteClosed) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Session is closed';
            sendRoger(res, rinfo);
            return;
          }
          res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Cache-Control': 'no-store',
            'Connection': 'Keep-Alive',
          });
          let closed = false;
          let timer = null;
          let lastHeartbeat = Date.now();
          const heartbeatIntervalMs = 5000;
          const closeDownlink = () => {
            closed = true;
            if (timer) {
              clearInterval(timer);
            }
          };
          res.on('close', closeDownlink);
          timer = setInterval(() => {
            if (closed) {
              return;
            }
            const current = states.get(mark);
            if (!current || (!current.run && !hasBufferedData(current) && !current.remoteWriteClosed)) {
              clearInterval(timer);
              res.end();
              return;
            }
            if (current.kind === 'udp') {
              const packet = current.udpQueue.shift();
              if (packet) {
                const frame = {};
                frame[STATUS] = 'OK';
                frame[CMD] = 'DATA';
                frame[DATA] = packet.data;
                if (packet.meta) {
                  frame[UDPFRAG] = packet.meta;
                }
                frame[IP] = packet.peer.address;
                frame[PORT] = String(packet.peer.port);
                writeStreamFrame(res, current, frame);
                return;
              }
            } else {
              if (current.readbuf.length > 0) {
                const frame = {};
                frame[STATUS] = 'OK';
                frame[CMD] = 'DATA';
                frame[DATA] = current.readbuf;
                current.readbuf = Buffer.alloc(0);
                writeStreamFrame(res, current, frame);
                return;
              }
              if (current.settings.halfClose && current.remoteWriteClosed && !current.remoteWriteNotified) {
                current.remoteWriteNotified = true;
                const frame = {};
                frame[STATUS] = 'OK';
                frame[CMD] = 'SHUT_WR';
                writeStreamFrame(res, current, frame);
                return;
              }
            }
            const now = Date.now();
            if (now - lastHeartbeat < heartbeatIntervalMs) {
              return;
            }
            const heartbeat = {};
            heartbeat[STATUS] = 'OK';
            heartbeat[CMD] = 'HEARTBEAT';
            writeStreamFrame(res, current, heartbeat);
            lastHeartbeat = now;
          }, 50);
          break;
        }

        case 'FORWARD': {
          const state = states.get(mark);
          const rawPostData = info[DATA] || Buffer.alloc(0);
          if (!state || !state.run) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Session is closed';
            sendRoger(res, rinfo);
            return;
          }
          if (rawPostData.length === 0) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'POST data parse error';
            sendRoger(res, rinfo);
            return;
          }

          if (state.kind === 'udp') {
            const target = info[IP] ? info[IP].toString() : null;
            const port = info[PORT] ? parseInt(info[PORT].toString(), 10) : null;
            if (!target || Number.isNaN(port)) {
              rinfo[STATUS] = 'FAIL';
              rinfo[ERROR] = 'Missing UDP peer';
              sendRoger(res, rinfo);
              return;
            }
            const packet = udpReassembleFragment(state, rawPostData, info[UDPFRAG]);
            if (!packet.complete) {
              touchUdpState(state);
              rinfo[STATUS] = 'OK';
              res.setHeader('Connection', 'Keep-Alive');
              sendRoger(res, rinfo);
              return;
            }
            touchUdpState(state);
            state.socket.send(packet.data, port, target, err => {
              if (err) {
                rinfo[STATUS] = 'FAIL';
                rinfo[ERROR] = err.message;
              } else {
                rinfo[STATUS] = 'OK';
                res.setHeader('Connection', 'Keep-Alive');
              }
              sendRoger(res, rinfo);
            });
          } else if (state.socket) {
            enqueueTcpWrite(state, rawPostData).then(ok => {
              if (!ok) {
                rinfo[STATUS] = 'FAIL';
                rinfo[ERROR] = 'Failed writing to target';
              } else {
                rinfo[STATUS] = 'OK';
                res.setHeader('Connection', 'Keep-Alive');
              }
              sendRoger(res, rinfo);
            });
          } else {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Session is not connected';
            sendRoger(res, rinfo);
          }
          break;
        }

        case 'DISCONNECT': {
          closeState(mark, states.get(mark));
          rinfo[STATUS] = 'OK';
          sendRoger(res, rinfo);
          break;
        }

        case 'SHUT_WR': {
          const state = states.get(mark);
          if (!state || !state.settings.halfClose) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Half-close mode is disabled';
            sendRoger(res, rinfo);
            return;
          }
          if (!state || !state.run || state.kind !== 'tcp' || !state.socket) {
            rinfo[STATUS] = 'FAIL';
            rinfo[ERROR] = 'Session is closed';
            sendRoger(res, rinfo);
            return;
          }
          enqueueTcpShutdownWrite(state).then(ok => {
            rinfo[STATUS] = 'OK';
            if (!ok) {
              rinfo[STATUS] = 'FAIL';
              rinfo[ERROR] = 'Failed shutting down target write side';
            }
            res.setHeader('Connection', 'Keep-Alive');
            sendRoger(res, rinfo);
          });
          break;
        }

        default:
          sendHello(res);
          break;
      }
  }

  function handleRequest(req, res, initialBody = '') {
    let body = initialBody;
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => handleClassicBody(res, body));
  }

  function handleProtocolRequest(req, res) {
    let probeBuffer = Buffer.alloc(0);
    let decided = false;

    const fallbackClassic = () => {
      if (decided) {
        return;
      }
      decided = true;
      handleRequest(req, res, probeBuffer.toString());
    };

    req.on('data', chunk => {
      if (decided) {
        return;
      }
      probeBuffer = Buffer.concat([probeBuffer, chunk]);
      if (probeBuffer.length < 8) {
        return;
      }
      const frameLen = parseInt(probeBuffer.slice(0, 8).toString(), 16);
      if (!Number.isFinite(frameLen) || frameLen < 0) {
        fallbackClassic();
        return;
      }
      if (probeBuffer.length < 8 + frameLen) {
        return;
      }
      try {
        const first = decodeStreamFrame(probeBuffer.slice(8, 8 + frameLen));
        const cmd = first[CMD] ? first[CMD].toString() : '';
        if (cmd === 'DUPLEX' || cmd === 'PROBE') {
          decided = true;
          handleFullDuplex(req, res, probeBuffer);
        } else {
          fallbackClassic();
        }
      } catch (_) {
        fallbackClassic();
      }
    });

    req.on('end', () => {
      if (!decided) {
        decided = true;
        handleClassicBody(res, probeBuffer.toString());
      }
    });
  }

  globalThis.__rogerHandleProtocolRequest = handleProtocolRequest;

  function installServerHook(serverPrototype) {
    const originalEmit = serverPrototype.emit;
    serverPrototype.emit = function (event, ...args) {
      if (event === 'request') {
        const [req, res] = args;
        const scheme = req.socket && req.socket.encrypted ? 'https' : 'http';
        const parsedUrl = new URL(req.url, `${scheme}://${req.headers.host}`);
        if (parsedUrl.pathname === path) {
          handleProtocolRequest(req, res);
          return true;
        }
      }
      return originalEmit.apply(this, arguments);
    };
  }

  installServerHook(http.Server.prototype);
  installServerHook(https.Server.prototype);
})();
