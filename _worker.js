import { connect } from "cloudflare:sockets";

// Variables
let serviceName = "";
let APP_DOMAIN = "";
let prxIP = "";
let cachedPrxList = [];

// Constant
const horse = "dHJvamFu";
const flash = "dm1lc3M=";
const neko = "dmxlc3M=";
const v2 = "djJyYXk=";

const PORTS = [443, 80];
const PROTOCOLS = [atob(horse), atob(flash), atob(neko), "ss"];
const SUB_PAGE_URL = "https://foolvpn.web.id/nautica";
const KV_PRX_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";
const PRX_BANK_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt";
const DNS_SERVER_ADDRESS = "174.138.21.128";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = { host: "udp-relay.hobihaus.space", port: 7300 };
const CONVERTER_URL = "https://api.foolvpn.web.id/convert";
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// Encrypted Stream Constants (Base64 Encoded)
const SALT_A1 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgS2V5X0xlbmd0aA==");
const SALT_A2 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgTm9uY2VfTGVuZ3Ro");
const SALT_A3 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgS2V5");
const SALT_A4 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgTm9uY2U=");
const SALT_B1 = atob("QUVBRCBSZXNwIEhlYWRlciBMZW4gS2V5");
const SALT_B2 = atob("QUVBRCBSZXNwIEhlYWRlciBMZW4gSVY=");
const SALT_B3 = atob("QUVBRCBSZXNwIEhlYWRlciBLZXk=");
const SALT_B4 = atob("QUVBRCBSZXNwIEhlYWRlciBJVg==");

// --- Custom Health Check Menggunakan TCP Socket ---
async function isProxyAlive(ip, port) {
  try {
    const socket = connect({ hostname: ip, port: parseInt(port) });
    // Timeout 2.5 Detik
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error("Timeout")), 2500)
    );
    await Promise.race([socket.opened, timeoutPromise]);
    socket.close(); // Tutup jika hidup
    return true;
  } catch (err) {
    return false;
  }
}

async function getPrxList(prxBankUrl = PRX_BANK_URL) {
  if (!prxBankUrl) throw new Error("No URL Provided!");
  const prxBank = await fetch(prxBankUrl);
  if (prxBank.status == 200) {
    const text = (await prxBank.text()) || "";
    const prxString = text.split("\n").filter(Boolean);
    cachedPrxList = prxString
      .map((entry) => {
        const [prxIP, prxPort, country, org] = entry.split(",");
        return {
          prxIP: prxIP || "Unknown",
          prxPort: prxPort || "Unknown",
          country: country || "Unknown",
          org: org || "Unknown Org",
        };
      })
      .filter(Boolean);
  }
  return cachedPrxList;
}

async function reverseWeb(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");
  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

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

// --- Fungsi Sync Kuota Hemat (JSON Bundling) ---
async function syncProxiesToKV(env) {
  if (!env.PROXY_DB) return { error: "PROXY_DB tidak ditemukan" };

  const proxies = await getPrxList(PRX_BANK_URL);
  
  // Prioritas Urutan Pengecekan
  const priorityCC = ["ID", "MY", "SG"];
  const ccGroup = { ID: [], MY: [], SG: [] };

  for (const prx of proxies) {
    const cc = prx.country.toUpperCase();
    if (priorityCC.includes(cc)) {
      ccGroup[cc].push(prx);
    }
  }

  let dictProxies = {};
  let displayLines = [];
  let totalSaved = 0;

  for (const cc of priorityCC) {
    const proxyList = ccGroup[cc];
    let count = 1;

    // Cek paralel maksimal 15 per negara agar aman dari limit timeout Worker
    const toCheck = proxyList.slice(0, 15);
    const checkPromises = toCheck.map(async (prx) => {
      const isAlive = await isProxyAlive(prx.prxIP, prx.prxPort);
      return { ...prx, isAlive };
    });

    const checkResults = await Promise.all(checkPromises);

    for (const result of checkResults) {
      if (result.isAlive) {
        const keyName = `${cc.toLowerCase()}${count}`; // contoh: id1, my1, sg1
        const ipPort = `${result.prxIP}-${result.prxPort}`;
        
        // Simpan ke kamus JSON
        dictProxies[keyName] = ipPort;
        
        // Simpan ke format tampilan: SG sg1=1.1.1.1-443 Cloudflare limited
        displayLines.push(`${cc} ${keyName}=${ipPort} ${result.org}`);
        count++;
        totalSaved++;
      }
    }
  }

  // Hanya 2 kali operasi PUT, sangat menghemat limit 1.000 KV/hari
  await env.PROXY_DB.put("ALL_ACTIVE_PROXIES", JSON.stringify(dictProxies));
  
  const webContent = displayLines.length > 0 ? displayLines.join("\n") : "Tidak ada proxy aktif saat ini.";
  await env.PROXY_DB.put("HOMEPAGE_CACHE", webContent);

  return { 
    status: "success", 
    total_active_saved: totalSaved,
    db_updated: true
  };
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0];

      const upgradeHeader = request.headers.get("Upgrade");

      if (url.pathname === "/sync-db") {
        if (!env.PROXY_DB) return new Response("Error: KV Namespace 'PROXY_DB' belum di-bind!", { status: 500 });
        const syncResult = await syncProxiesToKV(env);
        return new Response(JSON.stringify(syncResult), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.pathname === "/" && upgradeHeader !== "websocket") {
        if (!env.PROXY_DB) return new Response("Error: KV 'PROXY_DB' belum di-bind!", { status: 500 });
        const cache = await env.PROXY_DB.get("HOMEPAGE_CACHE");
        return new Response(cache || "Menunggu sinkronisasi pertama selesai. Kunjungi /sync-db untuk memuat data.", {
          status: 200,
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            ...CORS_HEADER_OPTIONS
          }
        });
      }

      // Handle WebSocket VPN Tunneling
      if (upgradeHeader === "websocket") {
        const reqPath = url.pathname.replace(/^\/+/, '').toLowerCase();
        const ipPortMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (ipPortMatch && !/^[a-z]+\d+$/.test(reqPath)) {
          prxIP = ipPortMatch[1];
        } 
        // Routing Dinamis menggunakan Kamus JSON dari KV (Contoh path: /sg1)
        else if (/^[a-z]+\d+$/.test(reqPath)) {
          if (env.PROXY_DB) {
            const dictStr = await env.PROXY_DB.get("ALL_ACTIVE_PROXIES");
            if (dictStr) {
              const dict = JSON.parse(dictStr);
              prxIP = dict[reqPath] ? dict[reqPath] : "1.1.1.1-443";
            } else {
              prxIP = "1.1.1.1-443";
            }
          } else {
            prxIP = "1.1.1.1-443";
          }
        } 
        else {
           prxIP = "1.1.1.1-443";
        }

        return await websocketHandler(request);
      }

      // Bypass /check as we handle health custom now
      if (url.pathname.startsWith("/sub") || url.pathname.startsWith("/check") || url.pathname.startsWith("/api/v1")) {
         return new Response("Not implemented in this optimized worker version.", { status: 404 });
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
    ctx.waitUntil(syncProxiesToKV(env));
  }
};

// ==========================================
// KODE INTI WEBSOCKET & PROTOKOL VPN TETAP SAMA
// ==========================================
async function websocketHandler(request) {
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

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log, RELAY_SERVER_UDP);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === atob(horse)) protocolHeader = readHorseHeader(chunk);
          else if (protocol === atob(flash)) protocolHeader = await readStreamHeader(chunk);
          else if (protocol === atob(neko)) protocolHeader = readNekoHeader(chunk);
          else if (protocol === "ss") protocolHeader = readSsHeader(chunk);
          else throw new Error("Unknown Protocol!");

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) throw new Error(protocolHeader.message);

          let responseHeader = protocolHeader.version;
          if (protocol === atob(flash) && protocolHeader.needsResponse) {
            responseHeader = await generateStreamResponseHeader(protocolHeader.responseOptions, protocolHeader.encKey, protocolHeader.encIv);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
              return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, responseHeader, log, RELAY_SERVER_UDP);
            }
            return handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, responseHeader, log, RELAY_SERVER_UDP);
          }

          handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, responseHeader, log);
        },
        close() { log(`readableWebSocketStream is close`); },
        abort(reason) { log(`readableWebSocketStream is abort`, JSON.stringify(reason)); },
      }),
    )
    .catch((err) => { log("readableWebSocketStream pipeTo error", err); });

  return new Response(null, { status: 101, webSocket: client });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
        if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) return atob(horse);
      }
    }
  }
  if (buffer.byteLength >= 18) {
    const version = new Uint8Array(buffer.slice(0, 1))[0];
    if (version === 0) {
      const protocolUuid = new Uint8Array(buffer.slice(1, 17));
      if (arrayBufferToHex(protocolUuid).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) return atob(neko);
    }
  }
  if (buffer.byteLength >= 42) {
    const firstByte = new Uint8Array(buffer.slice(0, 1))[0];
    if (firstByte === 0x01 || firstByte === 0x03 || firstByte === 0x04) return "ss";
    return atob(flash);
  }
  return "ss";
}

async function generateStreamResponseHeader(responseOptions, encKey, encIv) {
  try {
    const key = (await sha256(encKey)).slice(0, 16);
    const iv = (await sha256(encIv)).slice(0, 16);
    const lengthKey = (await kdf(key, [SALT_B1])).slice(0, 16);
    const lengthIv = (await kdf(iv, [SALT_B2])).slice(0, 12);
    const lengthData = new Uint8Array(2);
    lengthData[0] = 0; lengthData[1] = 4;
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
    return new Uint8Array(0);
  }
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const targetHost = prxIP.split(/[:=-]/)[0] || addressRemote;
    const targetPort = prxIP.split(/[:=-]/)[1] || portRemote;
    const tcpSocket = await connectAndWrite(targetHost, targetPort);
    tcpSocket.closed.catch((error) => { console.log("retry tcpSocket closed error", error); }).finally(() => { safeCloseWebSocket(webSocket); });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
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
        close() { log(`UDP connection to ${targetAddress} closed`); },
        abort(reason) { console.error(`UDP connection aborted due to ${reason}`); },
      }),
    );
  } catch (e) {
    console.error(`Error while handling UDP outbound: ${e.message}`);
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
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
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
  return stream;
}

async function md5(...inputs) {
  const combined = new Uint8Array(inputs.reduce((acc, input) => acc + input.length, 0));
  let offset = 0;
  for (const input of inputs) {
    combined.set(new Uint8Array(input), offset);
    offset += input.length;
  }
  const hashBuffer = await crypto.subtle.digest("MD5", combined);
  return new Uint8Array(hashBuffer);
}

async function sha256(input) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(hashBuffer);
}

async function kdf(key, path) {
  async function recursiveHash(keyBytes, innerHashFn) {
    return async (data) => {
      const ipad = new Uint8Array(64); const opad = new Uint8Array(64);
      ipad.set(keyBytes.slice(0, Math.min(64, keyBytes.length)));
      opad.set(keyBytes.slice(0, Math.min(64, keyBytes.length)));
      for (let i = 0; i < 64; i++) { ipad[i] ^= 0x36; opad[i] ^= 0x5c; }
      const innerData = new Uint8Array(ipad.length + data.length);
      innerData.set(ipad); innerData.set(data, ipad.length);
      const innerResult = await innerHashFn(innerData);
      const outerData = new Uint8Array(opad.length + innerResult.length);
      outerData.set(opad); outerData.set(innerResult, opad.length);
      return await innerHashFn(outerData);
    };
  }
  const sha256Hash = async (data) => { return new Uint8Array(await crypto.subtle.digest("SHA-256", data)); };
  let currentHashFn = await recursiveHash(new TextEncoder().encode("VMess AEAD KDF"), sha256Hash);
  for (const salt of path) {
    const saltBytes = typeof salt === "string" ? new TextEncoder().encode(salt) : new Uint8Array(salt);
    currentHashFn = await recursiveHash(saltBytes, currentHashFn);
  }
  return await currentHashFn(key);
}

async function aesGcmDecrypt(key, nonce, data, aad) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, cryptoKey, data);
  return new Uint8Array(decrypted);
}

async function aesGcmEncrypt(key, nonce, data, aad) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, cryptoKey, data);
  return new Uint8Array(encrypted);
}

async function readStreamHeader(buffer) {
  try {
    const uuidString = "00000000-0000-0000-0000-000000000000";
    const uuidBytes = new Uint8Array(uuidString.replace(/-/g, "").match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
    const authKey = await md5(uuidBytes, new TextEncoder().encode(atob("YzQ4NjE5ZmUtOGYwMi00OWUwLWI5ZTktZWRmNzYzZTE3ZTIx")));

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
    if (version !== 1) return { hasError: true, message: `Invalid protocol version: ${version}` };

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
        addressRemote = `${view.getUint8(offset)}.${view.getUint8(offset + 1)}.${view.getUint8(offset + 2)}.${view.getUint8(offset + 3)}`;
        offset += 4; break;
      case 2:
      case 3:
        const domainLength = view.getUint8(offset); offset += 1;
        addressRemote = new TextDecoder().decode(headerPayload.slice(offset, offset + domainLength));
        offset += domainLength; break;
      case 4:
        const ipv6Parts = [];
        for (let i = 0; i < 8; i++) ipv6Parts.push(view.getUint16(offset + i * 2, false).toString(16));
        addressRemote = ipv6Parts.join(":"); offset += 16; break;
      default: return { hasError: true, message: `Invalid address type` };
    }

    const rawDataIndex = 42 + headerLength + 16;
    return {
      hasError: false, addressRemote, addressType, portRemote, rawDataIndex, rawClientData: buffer.slice(rawDataIndex),
      version: new Uint8Array([options[0], 0]), isUDP, needsResponse: true, responseOptions: options, encKey: encKey, encIv: encIv,
    };
  } catch (e) {
    return { hasError: true, message: "Stream header parsing failed" };
  }
}

function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer);
  const addressType = view.getUint8(0);
  let addressLength = 0; let addressValueIndex = 1; let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":"); break;
    default: return { hasError: true, message: `Invalid addressType` };
  }
  const portIndex = addressValueIndex + addressLength;
  const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote,
    rawDataIndex: portIndex + 2, rawClientData: ssBuffer.slice(portIndex + 2), version: null, isUDP: portRemote == 53,
  };
}

function readNekoHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  let isUDP = false;
  const optLength = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else return { hasError: true, message: `command not supported` };

  const portIndex = 18 + optLength + 1;
  const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressType = buffer[addressIndex];
  let addressLength = 0; let addressValueIndex = addressIndex + 1; let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
    case 2:
      addressLength = buffer[addressValueIndex]; addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":"); break;
    default: return { hasError: true, message: `invalid addressType` };
  }
  return {
    hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength, rawClientData: buffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]), isUDP: isUDP,
  };
}

function readHorseHeader(buffer) {
  const dataBuffer = buffer.slice(58);
  if (dataBuffer.byteLength < 6) return { hasError: true, message: "invalid request data" };

  let isUDP = false;
  const view = new DataView(dataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) { isUDP = true; } else if (cmd != 1) { throw new Error("Unsupported command"); }

  let addressType = view.getUint8(1);
  let addressLength = 0; let addressValueIndex = 2; let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
    case 3:
      addressLength = dataBuffer[addressValueIndex]; addressValueIndex += 1;
      addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":"); break;
    default: return { hasError: true, message: `invalid addressType` };
  }
  const portIndex = addressValueIndex + addressLength;
  const portRemote = new DataView(dataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
  return {
    hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote,
    rawDataIndex: portIndex + 4, rawClientData: dataBuffer.slice(portIndex + 4), version: null, isUDP: isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          hasIncomingData = true;
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {}, abort(reason) {},
      }),
    )
    .catch((error) => { safeCloseWebSocket(webSocket); });
  if (hasIncomingData === false && retry) { retry(); }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) { socket.close(); }
  } catch (error) {}
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) { return { error }; }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
