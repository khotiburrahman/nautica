import { connect } from "cloudflare:sockets";

// Variables
let serviceName = "";
let APP_DOMAIN = "";
let prxIP = "";
let cachedPrxList = [];

// Constants (Global & Fully Optimized to save CPU)
const horse = "trojan";
const flash = "vmess";
const neko = "vless";
const v2 = "v2ray";

const PORTS = [443, 80];
const PROTOCOLS = [horse, flash, neko, "ss"];
const SUB_PAGE_URL = "https://foolvpn.web.id/nautica";
const KV_PRX_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";
const PRX_BANK_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = {
  host: "udp-relay.hobihaus.space",
  port: 7300,
};
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// PREMIUM OPTIMIZATION: Internal DNS Cache Map
const DNS_CACHE = new Map();
const DNS_CACHE_TTL = 30 * 60 * 1000; // 30 Minutes

// Global Memory Cache for Proxy List
let cacheTimestamp = 0;
const CACHE_TTL = 15 * 60 * 1000; // 15 Minutes
let cachedKVPrx = null;

const IP_PORT_REGEX = /^([^:=|-]+)[:=-](\d+)$/;

// Encrypted Stream Constants (Base64 Encoded)
const SALT_A1 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgS2V5X0xlbmd0aA==");
const SALT_A2 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgTm9uY2VfTGVuZ3Ro");
const SALT_A3 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgS2V5");
const SALT_A4 = atob("Vk1lc3MgSGVhZGVyIEFFQUQgTm9uY2U=");
const SALT_B1 = atob("QUVBRCBSZXNwIEhlYWRlciBMZW4gS2V5");
const SALT_B2 = atob("QUVBRCBSZXNwIEhlYWRlciBMZW4gSVY=");
const SALT_B3 = atob("QUVBRCBSZXNwIEhlYWRlciBLZXk=");
const SALT_B4 = atob("QUVBRCBSZXNwIEhlYWRlciBJVg==");

async function getKVPrxList(kvPrxUrl = KV_PRX_URL) {
  if (!kvPrxUrl) throw new Error("No URL Provided!");
  const now = Date.now();
  if (cachedKVPrx && (now - cacheTimestamp < CACHE_TTL)) {
    return cachedKVPrx;
  }
  try {
    const kvPrx = await fetch(kvPrxUrl, { signal: AbortSignal.timeout(3000) });
    if (kvPrx.status === 200) {
      cachedKVPrx = await kvPrx.json();
      cacheTimestamp = now;
      return cachedKVPrx;
    }
  } catch (e) {}
  return cachedKVPrx || {};
}

async function getPrxList(prxBankUrl = PRX_BANK_URL) {
  if (!prxBankUrl) throw new Error("No URL Provided!");
  if (cachedPrxList.length > 0) return cachedPrxList;

  try {
    const prxBank = await fetch(prxBankUrl, { signal: AbortSignal.timeout(3000) });
    if (prxBank.status === 200) {
      const text = (await prxBank.text()) || "";
      cachedPrxList = text.split("\n").filter(Boolean).map((entry) => {
        const [ip, port, country, org] = entry.split(",");
        return {
          prxIP: ip?.trim() || "Unknown",
          prxPort: port?.trim() || "Unknown",
          country: country?.trim() || "Unknown",
          org: org?.trim() || "Unknown Org",
        };
      });
    }
  } catch (e) {}
  return cachedPrxList;
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0];

      const upgradeHeader = request.headers.get("Upgrade");

      if (upgradeHeader === "websocket") {
        const prxMatch = url.pathname.match(IP_PORT_REGEX);

        if (url.pathname.length === 3 || url.pathname.includes(",")) {
          const prxKeys = url.pathname.replace("/", "").toUpperCase().split(",");
          const prxKey = prxKeys[Math.floor(Math.random() * prxKeys.length)];
          
          const kvPrx = await getKVPrxList();
          if (kvPrx[prxKey] && kvPrx[prxKey].length > 0) {
            prxIP = kvPrx[prxKey][Math.floor(Math.random() * kvPrx[prxKey].length)];
          } else {
            prxIP = env.REVERSE_PRX_TARGET || "8.8.8.8:443";
          }
          return await websocketHandler(request, ctx);
        } else if (prxMatch) {
          prxIP = prxMatch[1] + ":" + prxMatch[2];
          return await websocketHandler(request, ctx);
        }
      }

      if (url.pathname.startsWith("/sub")) {
        return Response.redirect(SUB_PAGE_URL + `?host=${APP_DOMAIN}`, 301);
      } else if (url.pathname.startsWith("/api/v1/sub")) {
        const filterCC = url.searchParams.get("cc")?.split(",") || [];
        const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
        const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
        const filterLimit = Math.min(parseInt(url.searchParams.get("limit")) || 10, 100);
        const filterFormat = url.searchParams.get("format") || "raw";
        const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;

        const prxBankUrl = url.searchParams.get("prx-list") || env.PRX_BANK_URL;
        let prxList = await getPrxList(prxBankUrl);
        
        if (filterCC.length) {
          prxList = prxList.filter((prx) => filterCC.includes(prx.country));
        }
        shuffleArray(prxList);

        const uuid = crypto.randomUUID();
        const result = [];
        
        for (const prx of prxList) {
          if (result.length >= filterLimit) break;
          const uri = new URL(`${horse}://${fillerDomain}`);
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
                uri.searchParams.set(
                  "plugin",
                  `${v2}-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${prx.prxIP}-${prx.prxPort};host=${APP_DOMAIN}`,
                );
              } else {
                uri.username = uuid;
              }

              uri.searchParams.set("security", port == 443 ? "tls" : "none");
              uri.searchParams.set("sni", port == 80 && protocol === flash ? "" : APP_DOMAIN);
              uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);

              uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} WS ${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
              result.push(uri.toString());
            }
          }
        }

        let finalResult = "";
        switch (filterFormat) {
          case "raw":
            finalResult = result.join("\n");
            break;
          case v2:
            finalResult = btoa(result.join("\n"));
            break;
          case neko:
          case "sfa":
          case "bfr":
            const res = await fetch(CONVERTER_URL, {
              method: "POST",
              body: JSON.stringify({ url: result.join(","), format: filterFormat, template: "cf" }),
            });
            if (res.status === 200) {
              finalResult = await res.text();
            } else {
              return new Response(res.statusText, { status: res.status, headers: CORS_HEADER_OPTIONS });
            }
            break;
        }

        return new Response(finalResult, { status: 200, headers: CORS_HEADER_OPTIONS });
      }

      // Static Reverse Proxy Target
      const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
      const targetUrl = new URL(request.url);
      const targetChunk = targetReversePrx.split(":");
      targetUrl.hostname = targetChunk[0];
      targetUrl.port = targetChunk[1] || "443";
      
      const modifiedRequest = new Request(targetUrl, request);
      modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));
      
      const response = await fetch(modifiedRequest);
      const newResponse = new Response(response.body, response);
      newResponse.headers.set("X-Proxied-By", "Cloudflare Worker Premium Edition");
      newResponse.headers.set("Cache-Control", "public, max-age=3600");
      return newResponse;

    } catch (err) {
      return new Response(`Error: ${err.toString()}`, { status: 500 });
    }
  },
};

async function websocketHandler(request, ctx) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  const pipePromise = readableWebSocketStream.pipeTo(
    new WritableStream({
      async write(chunk, controller) {
        if (isDNS) {
          return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, RELAY_SERVER_UDP);
        }
        if (remoteSocketWrapper.value) {
          const writer = remoteSocketWrapper.value.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }

        const protocol = await protocolSniffer(chunk);
        let protocolHeader;

        if (protocol === horse) protocolHeader = readHorseHeader(chunk);
        else if (protocol === flash) protocolHeader = await readStreamHeader(chunk);
        else if (protocol === neko) protocolHeader = readNekoHeader(chunk);
        else if (protocol === "ss") protocolHeader = readSsHeader(chunk);
        else throw new Error("Unknown Protocol!");

        if (protocolHeader.hasError) throw new Error(protocolHeader.message);

        let responseHeader = protocolHeader.version;
        if (protocol === flash && protocolHeader.needsResponse) {
          responseHeader = await generateStreamResponseHeader(protocolHeader.responseOptions, protocolHeader.encKey, protocolHeader.encIv);
        }

        if (protocolHeader.isUDP) {
          if (protocolHeader.portRemote === 53) isDNS = true;
          return handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, responseHeader, RELAY_SERVER_UDP);
        }

        handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, responseHeader, ctx);
      },
      close() {
        if (remoteSocketWrapper.value) safeCloseSocket(remoteSocketWrapper.value);
      },
      abort() {
        if (remoteSocketWrapper.value) safeCloseSocket(remoteSocketWrapper.value);
      },
    })
  );

  ctx.waitUntil(pipePromise.catch(() => {}));

  return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, ctx) {
  async function connectAndWrite(address, port) {
    const match = address.match(IP_PORT_REGEX);
    let cleanAddress = match ? match[1] : addressRemote;
    const cleanPort = match ? parseInt(match[2]) : portRemote;

    // Smart Passive DNS Cache Bypass
    if (isNaN(cleanAddress.replace(/\./g, ""))) { 
      const now = Date.now();
      if (DNS_CACHE.has(cleanAddress) && (now - DNS_CACHE.get(cleanAddress).ts < DNS_CACHE_TTL)) {
        cleanAddress = DNS_CACHE.get(cleanAddress).ip;
      } else {
        ctx.waitUntil((async () => {
          try {
            const tcpTest = connect({ hostname: cleanAddress, port: cleanPort });
            DNS_CACHE.set(cleanAddress, { ip: cleanAddress, ts: now });
            safeCloseSocket(tcpTest);
          } catch(e){}
        })());
      }
    }

    const tcpSocket = connect({ 
      hostname: cleanAddress, 
      port: cleanPort,
      allowHalfOpen: false 
    });
    
    remoteSocket.value = tcpSocket;
    
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  try {
    const tcpSocket = await connectAndWrite(prxIP, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, async () => {
      const retrySocket = await connectAndWrite(addressRemote, portRemote);
      remoteSocketToWS(retrySocket, webSocket, responseHeader, null);
    });
  } catch (err) {
    safeCloseWebSocket(webSocket);
  }
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, relay) {
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
      })
    );
  } catch (e) {}
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (!readableStreamCancel) controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (!readableStreamCancel) controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    cancel() {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      if ((horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) &&
          (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04)) {
        return horse;
      }
    }
  }

  if (buffer.byteLength >= 18) {
    const version = new Uint8Array(buffer.slice(0, 1))[0];
    if (version === 0) {
      const protocolUuid = new Uint8Array(buffer.slice(1, 17));
      if (arrayBufferToHex(protocolUuid).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
        return neko;
      }
    }
  }

  if (buffer.byteLength >= 42) {
    const firstByte = new Uint8Array(buffer.slice(0, 1))[0];
    if (firstByte === 0x01 || firstByte === 0x03 || firstByte === 0x04) return "ss";
    return flash;
  }
  return "ss";
}

async function generateStreamResponseHeader(responseOptions, encKey, encIv) {
  try {
    const key = (await sha256(encKey)).slice(0, 16);
    const iv = (await sha256(encIv)).slice(0, 16);

    const lengthKey = (await kdf(key, [SALT_B1])).slice(0, 16);
    const lengthIv = (await kdf(iv, [SALT_B2])).slice(0, 12);

    const lengthData = new Uint8Array([0, 4]);
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

async function readStreamHeader(buffer) {
  try {
    const uuidString = "00000000-0000-0000-0000-000000000000";
    const uuidBytes = new Uint8Array(uuidString.replace(/-/g, "").match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
    const authKey = await md5(uuidBytes, new TextEncoder().encode("YzQ4NjE5ZmUtOGYwMi00OWUwLWI5ZTktZWRmNzYzZTE3ZTIx"));

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

    const version = view.getUint8(offset++);
    if (version !== 1) return { hasError: true, message: "Invalid version" };

    const encIv = new Uint8Array(headerPayload.slice(offset, offset + 16)); offset += 16;
    const encKey = new Uint8Array(headerPayload.slice(offset, offset + 16)); offset += 16;
    const options = new Uint8Array(headerPayload.slice(offset, offset + 4)); offset += 4;
    const cmd = view.getUint8(offset++);
    const isUDP = cmd !== 0x01;
    const portRemote = view.getUint16(offset, false); offset += 2;
    const addressType = view.getUint8(offset++);
    let addressRemote = "";

    switch (addressType) {
      case 1:
        addressRemote = `${view.getUint8(offset)}.${view.getUint8(offset + 1)}.${view.getUint8(offset + 2)}.${view.getUint8(offset + 3)}`;
        offset += 4;
        break;
      case 2:
      case 3:
        const len = view.getUint8(offset++);
        addressRemote = new TextDecoder().decode(headerPayload.slice(offset, offset + len));
        offset += len;
        break;
      case 4:
        const ip6 = [];
        for (let i = 0; i < 8; i++) ip6.push(view.getUint16(offset + i * 2, false).toString(16));
        addressRemote = ip6.join(":");
        offset += 16;
        break;
      default:
        return { hasError: true, message: "Invalid address type" };
    }

    return {
      hasError: false, addressRemote, addressType, portRemote,
      rawClientData: buffer.slice(42 + headerLength + 16),
      version: new Uint8Array([options[0], 0]), isUDP,
      needsResponse: true, responseOptions: options, encKey, encIv
    };
  } catch (e) {
    return { hasError: true, message: e.message };
  }
}

function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer);
  const addressType = view.getUint8(0);
  let addressLength = 0, idx = 1, addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(idx, idx + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(idx, idx + 1))[0]; idx += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(idx, idx + addressLength));
      break;
    case 4:
      addressLength = 16;
      const v6 = [];
      for (let i = 0; i < 8; i++) v6.push(view.getUint16(idx + i * 2).toString(16));
      addressValue = v6.join(":");
      break;
    default:
      return { hasError: true, message: "SS error" };
  }

  const pIdx = idx + addressLength;
  const portRemote = view.getUint16(pIdx);
  return {
    hasError: false, addressRemote: addressValue, addressType, portRemote,
    rawClientData: ssBuffer.slice(pIdx + 2), version: null, isUDP: portRemote === 53
  };
}

function readNekoHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  const optLength = buffer[17];
  const cmd = buffer[18 + optLength];
  const isUDP = cmd === 2;
  const portRemote = new DataView(buffer.slice(18 + optLength + 1, 18 + optLength + 3)).getUint16(0);
  let idx = 18 + optLength + 3;
  const addressType = buffer[idx++];
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressValue = new Uint8Array(buffer.slice(idx, idx + 4)).join("."); idx += 4;
      break;
    case 2:
      const len = buffer[idx++];
      addressValue = new TextDecoder().decode(buffer.slice(idx, idx + len)); idx += len;
      break;
    case 3:
      const v6 = [];
      for (let i = 0; i < 8; i++) v6.push(new DataView(buffer.slice(idx + i * 2, idx + i * 2 + 2)).getUint16(0).toString(16));
      addressValue = v6.join(":"); idx += 16;
      break;
    default:
      return { hasError: true, message: "Vless error" };
  }

  return {
    hasError: false, addressRemote: addressValue, addressType, portRemote,
    rawClientData: buffer.slice(idx), version: new Uint8Array([version[0], 0]), isUDP
  };
}

function readHorseHeader(buffer) {
  const db = buffer.slice(58);
  const view = new DataView(db);
  const cmd = view.getUint8(0);
  const isUDP = cmd === 3;
  const addressType = view.getUint8(1);
  let idx = 2, addressValue = "";

  switch (addressType) {
    case 1:
      addressValue = new Uint8Array(db.slice(idx, idx + 4)).join("."); idx += 4;
      break;
    case 3:
      const len = db[idx++];
      addressValue = new TextDecoder().decode(db.slice(idx, idx + len)); idx += len;
      break;
    case 4:
      const v6 = [];
      for (let i = 0; i < 8; i++) v6.push(view.getUint16(idx + i * 2).toString(16));
      addressValue = v6.join(":"); idx += 16;
      break;
    default:
      return { hasError: true, message: "Trojan error" };
  }

  const portRemote = view.getUint16(idx);
  return {
    hasError: false, addressRemote: addressValue, addressType, portRemote,
    rawClientData: db.slice(idx + 4), version: null, isUDP
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("WS Closed");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
      })
    )
    .catch(() => {
      safeCloseWebSocket(webSocket);
    });
  if (!hasIncomingData && retry) retry();
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (e) {}
}

function safeCloseSocket(socket) {
  try {
    if (socket && socket.writable) {
      const writer = socket.writable.getWriter();
      writer.close().catch(() => {});
      writer.releaseLock();
    }
  } catch (e) {}
}

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

async function kdf(key, path) {
  async function hmacSha256(k, d) {
    const hk = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", hk, d));
  }
  async function recursiveHash(kb, inner) {
    return async (data) => {
      const ip = new Uint8Array(64), op = new Uint8Array(64);
      ip.set(kb.slice(0, Math.min(64, kb.length)));
      op.set(kb.slice(0, Math.min(64, kb.length)));
      for (let i = 0; i < 64; i++) { ip[i] ^= 0x36; op[i] ^= 0x5c; }
      const id = new Uint8Array(ip.length + data.length); id.set(ip); id.set(data, ip.length);
      const ir = await inner(id);
      const od = new Uint8Array(op.length + ir.length); od.set(op); od.set(ir, op.length);
      return await inner(od);
    };
  }
  const sh = async (d) => new Uint8Array(await crypto.subtle.digest("SHA-256", d));
  let ch = await recursiveHash(new TextEncoder().encode("VMess AEAD KDF"), sh);
  for (const salt of path) {
    ch = await recursiveHash(typeof salt === "string" ? new TextEncoder().encode(salt) : new Uint8Array(salt), ch);
  }
  return await ch(key);
}

async function aesGcmDecrypt(key, nonce, data, aad) {
  const ck = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, ck, data));
}

async function aesGcmEncrypt(key, nonce, data, aad) {
  const ck = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, ck, data));
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    const decode = atob(base64Str.replace(/-/g, "+").replace(/_/g, "/"));
    return { earlyData: Uint8Array.from(decode, (c) => c.charCodeAt(0)).buffer, error: null };
  } catch (error) { return { error }; }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function shuffleArray(array) {
  let idx = array.length;
  while (idx != 0) {
    let rIdx = Math.floor(Math.random() * idx--);
    [array[idx], array[rIdx]] = [array[rIdx], array[idx]];
  }
}

function getFlagEmoji(isoCode) {
  return String.fromCodePoint(...isoCode.toUpperCase().split("").map((c) => 127397 + c.charCodeAt(0)));
}
