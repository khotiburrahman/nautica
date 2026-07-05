import { connect } from "cloudflare:sockets";

// ===== KONSTANTA & KONFIGURASI =====
const horse = "dHJvamFu"; // trojan
const flash = "dm1lc3M="; // vmess
const neko = "dmxlc3M="; // vless
const v2 = "djJyYXk="; // v2ray

const PORTS = [443, 80];
const PROTOCOLS = [atob(horse), atob(flash), atob(neko), "ss"];
const SUB_PAGE_URL = "https://foolvpn.web.id/nautica";
const GITHUB_RAW_URL = "https://raw.githubusercontent.com/khotiburrahman/auto_proxy/refs/heads/main/active_proxies.txt";

const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = { host: "udp-relay.hobihaus.space", port: 7300 };
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// VMess AEAD Salt Constants
const SALT_A1 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgS2V5X0xlbmd0aA==");
const SALT_A2 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgTm9uY2VfTGVuZ3Ro");
const SALT_A3 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgS2V5");
const SALT_A4 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgTm9uY2U=");
const SALT_B1 = atob("QUVBRCBSZXNwIEhlYWRlciBMZW4gS2V5");
const SALT_B2 = atob("QUVBRCBSZXNwIEhlYWRlciBMZW4gSVY=");
const SALT_B3 = atob("QUVBRCBSZXNwIEhlYWRlciBLZXk=");
const SALT_B4 = atob("QUVBRCBSZXNwIEhlYWRlciBJVg==");

// ===== FUNGSI SINKRONISASI GITHUB =====
async function syncGitHubToKV(env) {
  if (!env.PROXY_DB) return { error: "PROXY_DB tidak ditemukan" };
  const req = await fetch(GITHUB_RAW_URL);
  if (req.status === 200) {
    const text = await req.text();
    const lines = text.split('\n').filter(Boolean);
    const proxies = lines.map(line => {
      const [prxIP, prxPort, country, org] = line.split(',');
      return { prxIP, prxPort, country, org };
    });
    await env.PROXY_DB.put("PROXIES_JSON", JSON.stringify(proxies));
    await env.PROXY_DB.put("HOMEPAGE_CACHE", text);
    return { status: "success", total: proxies.length };
  }
  return { error: "Gagal mengambil data dari GitHub" };
}

// ===== REVERSE WEB =====
async function reverseWeb(request, target) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");
  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  const modifiedRequest = new Request(targetUrl, request);
  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));
  const response = await fetch(modifiedRequest);
  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");
  return newResponse;
}

// ===== UTILITY FUNCTIONS =====
async function md5(...inputs) {
  const combined = new Uint8Array(inputs.reduce((acc, input) => acc + input.length, 0));
  let offset = 0;
  for (const input of inputs) {
    combined.set(new Uint8Array(input), offset);
    offset += input.length;
  }
  return new Uint8Array(await crypto.subtle.digest("MD5", combined));
}

async function sha256(input) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

// KDF menggunakan HMAC-SHA256 (Iterated HMAC sesuai spesifikasi v2ray-core)
async function kdf(key, path) {
  let result = key;
  for (const salt of path) {
    const saltBytes = typeof salt === "string" ? new TextEncoder().encode(salt) : new Uint8Array(salt);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      result,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const hmac = await crypto.subtle.sign("HMAC", cryptoKey, saltBytes);
    result = new Uint8Array(hmac);
  }
  return result;
}

async function aesGcmDecrypt(key, nonce, data, aad) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, cryptoKey, data));
}

async function aesGcmEncrypt(key, nonce, data, aad) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, cryptoKey, data));
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    return { earlyData: Uint8Array.from(decode, (c) => c.charCodeAt(0)).buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {}
}

// ===== PROTOCOL HEADER PARSERS =====

// VMess AEAD Header Parser
async function readStreamHeader(buffer) {
  try {
    const uuidBytes = new Uint8Array(buffer.slice(0, 16));
    const salt = atob("YzQ4NjE5ZmUtOGYwMi00OWUwLWI5ZTktZWRmNzYzZTE3ZTIx");
    const authKey = await md5(uuidBytes, new TextEncoder().encode(salt));

    const authId = new Uint8Array(buffer.slice(0, 16));
    const encryptedLength = new Uint8Array(buffer.slice(16, 34));
    const nonce = new Uint8Array(buffer.slice(34, 42));

    const lengthKey = (await kdf(authKey, [SALT_A1, authId, nonce])).slice(0, 16);
    const lengthIv = (await kdf(authKey, [SALT_A2, authId, nonce])).slice(0, 12);
    const lengthBytes = await aesGcmDecrypt(lengthKey, lengthIv, encryptedLength, authId);
    const headerLength = (lengthBytes[0] << 8) | lengthBytes[1];

    const encryptedHeader = new Uint8Array(buffer.slice(42, 42 + headerLength + 16));
    const payloadKey = (await kdf(authKey, [SALT_A3, authId, nonce])).slice(0, 16);
    const payloadIv = (await kdf(authKey, [SALT_A4, authId, nonce])).slice(0, 12);
    const headerPayload = await aesGcmDecrypt(payloadKey, payloadIv, encryptedHeader, authId);

    const view = new DataView(headerPayload.buffer);
    let offset = 0;
    const version = view.getUint8(offset); offset += 1;
    if (version !== 1) return { hasError: true, message: "Unsupported version" };

    const encIv = new Uint8Array(headerPayload.slice(offset, offset + 16)); offset += 16;
    const encKey = new Uint8Array(headerPayload.slice(offset, offset + 16)); offset += 16;
    const options = new Uint8Array(headerPayload.slice(offset, offset + 4)); offset += 4;
    const cmd = view.getUint8(offset); offset += 1;
    const isUDP = cmd !== 0x01;
    const portRemote = view.getUint16(offset, false); offset += 2;

    const addressType = view.getUint8(offset); offset += 1;
    let addressRemote = "";
    switch (addressType) {
      case 1:
        addressRemote = `${view.getUint8(offset)}.${view.getUint8(offset+1)}.${view.getUint8(offset+2)}.${view.getUint8(offset+3)}`;
        offset += 4;
        break;
      case 2:
      case 3:
        const domainLength = view.getUint8(offset); offset += 1;
        addressRemote = new TextDecoder().decode(headerPayload.slice(offset, offset + domainLength));
        offset += domainLength;
        break;
      case 4:
        const ipv6Parts = [];
        for (let i = 0; i < 8; i++) {
          ipv6Parts.push(view.getUint16(offset + i*2, false).toString(16));
        }
        addressRemote = ipv6Parts.join(":");
        offset += 16;
        break;
      default:
        return { hasError: true, message: "Unknown address type" };
    }

    const rawDataIndex = 42 + headerLength + 16;
    return {
      hasError: false,
      addressRemote,
      addressType,
      portRemote,
      rawDataIndex,
      rawClientData: buffer.slice(rawDataIndex),
      version: new Uint8Array([options[0], 0]),
      isUDP,
      needsResponse: true,
      responseOptions: options,
      encKey: encKey,
      encIv: encIv,
    };
  } catch (e) {
    return { hasError: true, message: e.toString() };
  }
}

// Shadowsocks Header Parser (AEAD & Stream)
function readSsHeader(ssBuffer) {
  try {
    // Untuk AEAD: skip salt (16 bytes untuk AES-128/CHACHA20, 32 bytes untuk AES-256)
    // Untuk simplicity, kita asumsikan salt 16 bytes (AES-128-GCM)
    const saltLength = 16;
    const addressStart = saltLength;
    
    const view = new DataView(ssBuffer.slice(addressStart));
    const addressType = view.getUint8(0);
    let addressLength = 0, addressValueIndex = 1, addressValue = "";
    
    switch (addressType) {
      case 1: // IPv4
        addressLength = 4;
        addressValue = new Uint8Array(ssBuffer.slice(addressStart + addressValueIndex, addressStart + addressValueIndex + addressLength)).join(".");
        break;
      case 3: // Domain
        addressLength = new Uint8Array(ssBuffer.slice(addressStart + addressValueIndex, addressStart + addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(ssBuffer.slice(addressStart + addressValueIndex, addressStart + addressValueIndex + addressLength));
        break;
      case 4: // IPv6
        addressLength = 16;
        const dataView = new DataView(ssBuffer.slice(addressStart + addressValueIndex, addressStart + addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i*2).toString(16));
        addressValue = ipv6.join(":");
        break;
      default:
        return { hasError: true, message: "Unknown address type" };
    }
    
    const portIndex = addressStart + addressValueIndex + addressLength;
    const portRemote = new DataView(ssBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
    
    return {
      hasError: false,
      addressRemote: addressValue,
      addressType,
      portRemote,
      rawDataIndex: portIndex + 2,
      rawClientData: ssBuffer.slice(portIndex + 2),
      version: null,
      isUDP: portRemote === 53,
    };
  } catch (e) {
    return { hasError: true, message: e.toString() };
  }
}

// VLESS Header Parser
function readNekoHeader(buffer) {
  try {
    const version = new Uint8Array(buffer.slice(0, 1));
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
    const isUDP = cmd === 2;
    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);
    let addressIndex = portIndex + 2;
    const addressType = buffer[addressIndex];
    let addressLength = 0, addressValueIndex = addressIndex + 1, addressValue = "";
    
    switch (addressType) {
      case 1: // IPv4
        addressLength = 4;
        addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
        break;
      case 2: // Domain
        addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      case 3: // IPv6
        addressLength = 16;
        const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i*2).toString(16));
        addressValue = ipv6.join(":");
        break;
      default:
        return { hasError: true, message: "Unknown address type" };
    }
    
    return {
      hasError: false,
      addressRemote: addressValue,
      addressType,
      portRemote,
      rawDataIndex: addressValueIndex + addressLength,
      rawClientData: buffer.slice(addressValueIndex + addressLength),
      version: new Uint8Array([version[0], 0]),
      isUDP,
    };
  } catch (e) {
    return { hasError: true, message: e.toString() };
  }
}

// Trojan Header Parser (DIPERBAIKI: offset rawDataIndex)
function readHorseHeader(buffer) {
  try {
    const dataBuffer = buffer.slice(58);
    const view = new DataView(dataBuffer);
    const cmd = view.getUint8(0);
    const isUDP = cmd === 3;
    const addressType = view.getUint8(1);
    let addressLength = 0, addressValueIndex = 2, addressValue = "";
    
    switch (addressType) {
      case 1: // IPv4
        addressLength = 4;
        addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
        break;
      case 3: // Domain
        addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      case 4: // IPv6
        addressLength = 16;
        const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i*2).toString(16));
        addressValue = ipv6.join(":");
        break;
      default:
        return { hasError: true, message: "Unknown address type" };
    }
    
    const portIndex = addressValueIndex + addressLength;
    const portRemote = new DataView(dataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
    
    return {
      hasError: false,
      addressRemote: addressValue,
      addressType,
      portRemote,
      // DIPERBAIKI: Tambahkan 58 karena dataBuffer dimulai dari index 58 buffer asli
      rawDataIndex: 58 + portIndex + 4,
      rawClientData: dataBuffer.slice(portIndex + 4),
      version: null,
      isUDP,
    };
  } catch (e) {
    return { hasError: true, message: e.toString() };
  }
}

// Protocol Sniffer (DIPERBAIKI: hapus regex UUID ketat & false positive SS)
async function protocolSniffer(buffer) {
  // Deteksi Trojan (56-60 bytes delimiter)
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a &&
        (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) &&
        (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04)) {
      return atob(horse);
    }
  }
  
  // Deteksi VLESS (version byte = 0)
  if (buffer.byteLength >= 18) {
    const version = new Uint8Array(buffer.slice(0, 1))[0];
    if (version === 0) {
      return atob(neko);
    }
  }
  
  // Default ke VMess jika bukan Trojan/VLESS (DIPERBAIKI: hapus false positive SS)
  if (buffer.byteLength >= 42) {
    return atob(flash);
  }
  
  return "ss";
}

// VMess Response Header Generator (DIPERBAIKI: length data 2 bytes)
async function generateStreamResponseHeader(responseOptions, encKey, encIv) {
  try {
    const key = (await sha256(encKey)).slice(0, 16);
    const iv = (await sha256(encIv)).slice(0, 16);
    
    const lengthKey = (await kdf(key, [SALT_B1])).slice(0, 16);
    const lengthIv = (await kdf(iv, [SALT_B2])).slice(0, 12);
    // DIPERBAIKI: Length data seharusnya 2 bytes, bukan 4 bytes
    const lengthData = new Uint8Array([0x00, 0x04]); // 2 bytes, value = 4
    const encryptedLength = await aesGcmEncrypt(lengthKey, lengthIv, lengthData, new Uint8Array(0));
    
    const headerPayload = new Uint8Array([responseOptions[0], 0x00, 0x00, 0x00]);
    const payloadKey = (await kdf(key, [SALT_B3])).slice(0, 16);
    const payloadIv = (await kdf(iv, [SALT_B4])).slice(0, 12);
    const encryptedPayload = await aesGcmEncrypt(payloadKey, payloadIv, headerPayload, new Uint8Array(0));
    
    const response = new Uint8Array(encryptedLength.length + encryptedPayload.length);
    response.set(encryptedLength, 0);
    response.set(encryptedPayload, encryptedLength.length);
    return response;
  } catch (e) {
    console.error("generateStreamResponseHeader error:", e);
    return new Uint8Array([0x00, 0x00, 0x00, 0x00]);
  }
}

// ===== WEBSOCKET HANDLER =====
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) return;
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) return;
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {},
        abort(reason) {},
      }),
    );
  } catch (e) {
    // ignore
  }
  return hasIncomingData;
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, payload, webSocket, responseHeader, log, proxyIP, proxyPort) {
  let attempts = 0;
  const maxAttempts = 3;

  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    if (payload && payload.length > 0) {
      await writer.write(payload);
    }
    writer.releaseLock();
    return tcpSocket;
  }

  async function tryConnect() {
    attempts++;
    try {
      const targetAddress = (proxyIP && proxyPort) ? proxyIP : addressRemote;
      const targetPort = (proxyIP && proxyPort) ? proxyPort : portRemote;
      const tcpSocket = await connectAndWrite(targetAddress, targetPort);
      tcpSocket.closed.catch(() => {}).finally(() => { safeCloseWebSocket(webSocket); });
      const hasData = await remoteSocketToWS(tcpSocket, webSocket, responseHeader, log);
      if (!hasData && attempts < maxAttempts) {
        await new Promise(r => setTimeout(r, 1000 * attempts));
        tryConnect();
      } else if (!hasData && attempts >= maxAttempts) {
        safeCloseWebSocket(webSocket);
      }
    } catch (e) {
      if (attempts < maxAttempts) {
        await new Promise(r => setTimeout(r, 1000 * attempts));
        tryConnect();
      } else {
        safeCloseWebSocket(webSocket);
      }
    }
  }
  tryConnect();
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, log, relay) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({ hostname: relay.host, port: relay.port });
    const header = `udp:${targetAddress}:${targetPort}`;
    const headerBuffer = new TextEncoder().encode(header);
    const separator = new Uint8Array([0x7c]);
    const relayMessage = new Uint8Array(headerBuffer.length + separator.length + dataChunk.byteLength);
    relayMessage.set(headerBuffer, 0);
    relayMessage.set(separator, headerBuffer.length);
    relayMessage.set(new Uint8Array(dataChunk), headerBuffer.length + separator.length);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(relayMessage);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
        close() {},
        abort(reason) {},
      }),
    );
  } catch (e) {
    // ignore
  }
}

async function websocketHandler(request, env, proxyIP, proxyPort) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let addressLog = "";
  let portLog = "";
  const log = (info, event) => { console.log(`[${addressLog}:${portLog}] ${info}`, event || ""); };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  let buffer = new Uint8Array(0);
  let headerParsed = false;
  let protocolHeader = null;
  let responseHeader = null;
  let protocol = null;
  let initialPayload = null;

  const writableStream = new WritableStream({
    async write(chunk, controller) {
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const newBuffer = new Uint8Array(buffer.length + chunk.length);
      newBuffer.set(buffer);
      newBuffer.set(chunk, buffer.length);
      buffer = newBuffer;

      if (headerParsed) {
        if (!initialPayload) {
          initialPayload = new Uint8Array(0);
        }
        const newPayload = new Uint8Array(initialPayload.length + chunk.length);
        newPayload.set(initialPayload);
        newPayload.set(chunk, initialPayload.length);
        initialPayload = newPayload;
        return;
      }

      if (buffer.length < 62) {
        return;
      }

      protocol = await protocolSniffer(buffer);
      let parseResult;

      if (protocol === atob(horse)) {
        parseResult = readHorseHeader(buffer);
      } else if (protocol === atob(flash)) {
        parseResult = await readStreamHeader(buffer);
      } else if (protocol === atob(neko)) {
        parseResult = readNekoHeader(buffer);
      } else if (protocol === "ss") {
        parseResult = readSsHeader(buffer);
      } else {
        throw new Error("Unknown Protocol!");
      }

      if (parseResult.hasError) throw new Error(parseResult.message);

      protocolHeader = parseResult;
      addressLog = protocolHeader.addressRemote;
      portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

      if (protocol === atob(flash) && protocolHeader.needsResponse) {
        responseHeader = await generateStreamResponseHeader(
          protocolHeader.responseOptions,
          protocolHeader.encKey,
          protocolHeader.encIv
        );
      } else {
        responseHeader = protocolHeader.version || null;
      }

      headerParsed = true;

      const remaining = buffer.slice(protocolHeader.rawDataIndex);
      let payloadToSend = remaining;
      if (initialPayload && initialPayload.length > 0) {
        const combined = new Uint8Array(initialPayload.length + remaining.length);
        combined.set(initialPayload);
        combined.set(remaining, initialPayload.length);
        payloadToSend = combined;
      }
      initialPayload = payloadToSend;

      buffer = new Uint8Array(0);

      if (protocolHeader.isUDP) {
        if (protocolHeader.portRemote === 53) {
          isDNS = true;
          return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, responseHeader, log, RELAY_SERVER_UDP);
        }
        return handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, responseHeader, log, RELAY_SERVER_UDP);
      }

      handleTCPOutBound(
        remoteSocketWrapper,
        protocolHeader.addressRemote,
        protocolHeader.portRemote,
        initialPayload,
        webSocket,
        responseHeader,
        log,
        proxyIP,
        proxyPort
      );
    },
    close() {},
    abort(reason) {},
  });

  readableWebSocketStream.pipeTo(writableStream).catch((err) => {});

  return new Response(null, { status: 101, webSocket: client });
}

// ===== MAIN WORKER =====
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const APP_DOMAIN = url.hostname;
      const serviceName = APP_DOMAIN.split(".")[0];
      const upgradeHeader = request.headers.get("Upgrade");

      if (url.pathname === "/sync-db") {
        const result = await syncGitHubToKV(env);
        return new Response(JSON.stringify(result), {
          status: 200,
          headers: { "Content-Type": "application/json", ...CORS_HEADER_OPTIONS }
        });
      }

      let cachedPrxList = [];
      if (env.PROXY_DB) {
        cachedPrxList = await env.PROXY_DB.get("PROXIES_JSON", "json") || [];
      }

      if (url.pathname === "/" && upgradeHeader !== "websocket") {
        const cache = await env.PROXY_DB?.get("HOMEPAGE_CACHE");
        return new Response(cache || "Data belum sinkron. Akses /sync-db terlebih dahulu.", {
          status: 200,
          headers: { "Content-Type": "text/plain; charset=utf-8", ...CORS_HEADER_OPTIONS }
        });
      }

      if (upgradeHeader === "websocket") {
        const reqPath = url.pathname.replace(/^\/+/, '').toUpperCase();
        const ipPortMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        let proxyIP = null;
        let proxyPort = null;

        if (ipPortMatch && !/^[A-Z]+$/.test(reqPath)) {
          const [ip, port] = ipPortMatch[1].split(/[:=-]/);
          proxyIP = ip;
          proxyPort = parseInt(port);
        } else if (cachedPrxList.length > 0) {
          let availableProxies = cachedPrxList;
          if (/^[A-Z]+$/.test(reqPath)) {
            const filtered = cachedPrxList.filter(p => p.country.toUpperCase() === reqPath);
            if (filtered.length > 0) availableProxies = filtered;
          }
          const randomPrx = availableProxies[Math.floor(Math.random() * availableProxies.length)];
          proxyIP = randomPrx.prxIP;
          proxyPort = parseInt(randomPrx.prxPort);
        } else {
          proxyIP = "1.1.1.1";
          proxyPort = 443;
        }

        return await websocketHandler(request, env, proxyIP, proxyPort);
      }

      if (url.pathname.startsWith("/sub")) {
        return Response.redirect(SUB_PAGE_URL + `?host=${APP_DOMAIN}`, 301);
      } else if (url.pathname.startsWith("/api/v1/sub")) {
        const filterCC = url.searchParams.get("cc")?.split(",") || [];
        const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
        const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
        const filterLimit = parseInt(url.searchParams.get("limit")) || 10;
        const filterFormat = url.searchParams.get("format") || "raw";
        const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;

        let prxList = cachedPrxList;
        if (filterCC.length) prxList = prxList.filter((prx) => filterCC.includes(prx.country));

        let currentIndex = prxList.length;
        while (currentIndex != 0) {
          let randomIndex = Math.floor(Math.random() * currentIndex);
          currentIndex--;
          [prxList[currentIndex], prxList[randomIndex]] = [prxList[randomIndex], prxList[currentIndex]];
        }

        const uuid = crypto.randomUUID();
        const result = [];
        for (const prx of prxList) {
          const uri = new URL(`${atob(horse)}://${fillerDomain}`);
          uri.searchParams.set("encryption", "none");
          uri.searchParams.set("type", "ws");
          uri.searchParams.set("host", APP_DOMAIN);

          for (const port of filterPort) {
            for (const protocol of filterVPN) {
              if (result.length >= filterLimit) break;
              uri.protocol = protocol;
              uri.port = port.toString();
              if (protocol === "ss") {
                uri.username = btoa(`none:${uuid}`);
                uri.searchParams.set("plugin", `${atob(v2)}-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${prx.prxIP}-${prx.prxPort};host=${APP_DOMAIN}`);
              } else {
                uri.username = uuid;
              }
              uri.searchParams.set("security", port == 443 ? "tls" : "none");
              uri.searchParams.set("sni", port == 80 && protocol === atob(flash) ? "" : APP_DOMAIN);
              uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
              uri.hash = `${result.length + 1} WS ${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
              result.push(uri.toString());
            }
          }
        }

        let finalResult = result.join("\n");
        if (filterFormat !== "raw") {
          if (filterFormat === atob(v2)) finalResult = btoa(result.join("\n"));
        }

        return new Response(finalResult, { status: 200, headers: { ...CORS_HEADER_OPTIONS } });
      }

      const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
      return await reverseWeb(request, targetReversePrx);

    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: { ...CORS_HEADER_OPTIONS },
      });
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(syncGitHubToKV(env));
  }
};
