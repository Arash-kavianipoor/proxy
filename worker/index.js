// Cloudflare Pages / Worker for Arashproxysystem.ir
// Connected to Cloudflare D1 (a16983d7-1da3-4555-a1aa-f5730bccfcae)
// Supports: VLESS over WebSocket + /sub/:secret (V2Ray & INCY) + ProxyIP Relay + Anti-Probe
import { connect } from 'cloudflare:sockets';

const FALLBACK_UUIDS = new Set(["54aad0be-54d2-442e-9f4a-00f0bafe98ad","a9fbd798-2ed7-4042-825c-8db22dc6c428"]);
const FALLBACK_WS_PATHS = new Set(["/ws-5739ab8e","/incy-d53b4e9f","/tr-46c1592a","/vm-0699509b"]);
const FALLBACK_SUB_SECRET = 'a3affefe3827b8ba6fb5ae1f580676186ac14b8a7488e2a8';
const EMBEDDED_V2RAY_B64 = 'dmxlc3M6Ly81NGFhZDBiZS01NGQyLTQ0MmUtOWY0YS0wMGYwYmFmZTk4YWRAMTA0LjE2LjEzMi4yMjk6NDQzP2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT10bHMmc25pPUFyYXNocHJveHlzeXN0ZW0uaXImZnA9Y2hyb21lJmFscG49aHR0cCUyRjEuMSZ0eXBlPXdzJmhvc3Q9QXJhc2hwcm94eXN5c3RlbS5pciZwYXRoPSUyRndzLTU3MzlhYjhlJTNGZWQlM0QyMDQ4I0Nsb3VkZmxhcmUlMjBFZGdlJTIwUHJpbWFyeSUyMChWTEVTUyUyMCUyQiUyMEZyYWdtZW50KSUyMCU1QkFyYXNoUHJveHklNUQKdmxlc3M6Ly9hOWZiZDc5OC0yZWQ3LTQwNDItODI1Yy04ZGIyMmRjNmM0MjhAMTcyLjY0LjE1NS4xNDE6MjA1Mz9lbmNyeXB0aW9uPW5vbmUmc2VjdXJpdHk9dGxzJnNuaT1BcmFzaHByb3h5c3lzdGVtLmlyJmZwPXNhZmFyaSZhbHBuPWh0dHAlMkYxLjEmdHlwZT13cyZob3N0PUFyYXNocHJveHlzeXN0ZW0uaXImcGF0aD0lMkZpbmN5LWQ1M2I0ZTlmJTNGZWQlM0QyMDQ4I0lOQ1klMjBaZXJvLUxlYWslMjBUdW5uZWwlMjAoVkxFU1MlMjBUTFMpJTIwJTVCQXJhc2hQcm94eSU1RAp0cm9qYW46Ly9LTjFBcEdLOV9FZ2dsSUliUGtwNTRWRTFAMTA0LjE4LjIuMTYxOjg0NDM/c2VjdXJpdHk9dGxzJnNuaT1BcmFzaHByb3h5c3lzdGVtLmlyJmZwPWZpcmVmb3gmYWxwbj1odHRwJTJGMS4xJnR5cGU9d3MmaG9zdD1BcmFzaHByb3h5c3lzdGVtLmlyJnBhdGg9JTJGdHItNDZjMTU5MmElM0ZlZCUzRDIwNDgjQmFja3VwJTIwQW50aS1EUEklMjAoVHJvamFuJTIwV1MpJTIwJTVCQXJhc2hQcm94eSU1RAp2bWVzczovL2V5SjJJam9pTWlJc0luQnpJam9pVEdWbllXTjVJRU52YlhCaGRHbGliR1VnS0ZaTlpYTnpJRlJNVXlrZ1cwRnlZWE5vVUhKdmVIbGRJaXdpWVdSa0lqb2lNVFl5TGpFMU9TNHhNelV1TkRJaUxDSndiM0owSWpvaU5EUXpJaXdpYVdRaU9pSTBNRGxoTUdVNVppMWxOekpqTFRSbU9Ea3RPV0ZsTXkwME5XVTFZalF6WkROa09EUWlMQ0poYVdRaU9pSXdJaXdpYzJONUlqb2lZWFYwYnlJc0ltNWxkQ0k2SW5keklpd2lkSGx3WlNJNkltNXZibVVpTENKb2IzTjBJam9pUVhKaGMyaHdjbTk0ZVhONWMzUmxiUzVwY2lJc0luQmhkR2dpT2lJdmRtMHRNRFk1T1RVd09XSS9aV1E5TWpBME9DSXNJblJzY3lJNkluUnNjeUlzSW5OdWFTSTZJa0Z5WVhOb2NISnZlSGx6ZVhOMFpXMHVhWElpTENKaGJIQnVJam9pYUhSMGNDOHhMakVpTENKbWNDSTZJbU5vY205dFpTSjk=';
const EMBEDDED_INCY_JSON = "{\n  \"log\": {\n    \"level\": \"warn\",\n    \"timestamp\": true\n  },\n  \"dns\": {\n    \"servers\": [\n      {\n        \"tag\": \"doh-remote\",\n        \"address\": \"https://1.1.1.1/dns-query\",\n        \"address_resolver\": \"dns-bootstrap\",\n        \"detour\": \"ArashProxy-Secure\",\n        \"strategy\": \"ipv4_only\"\n      },\n      {\n        \"tag\": \"dns-bootstrap\",\n        \"address\": \"1.1.1.1\",\n        \"detour\": \"direct\"\n      },\n      {\n        \"tag\": \"dns-block\",\n        \"address\": \"rcode://success\"\n      }\n    ],\n    \"rules\": [\n      {\n        \"outbound\": \"any\",\n        \"server\": \"dns-bootstrap\"\n      },\n      {\n        \"protocol\": \"stun\",\n        \"server\": \"dns-block\"\n      }\n    ],\n    \"final\": \"doh-remote\",\n    \"independent_cache\": true\n  },\n  \"inbounds\": [\n    {\n      \"type\": \"tun\",\n      \"tag\": \"tun-in\",\n      \"inet4_address\": \"172.19.0.1/30\",\n      \"mtu\": 1400,\n      \"auto_route\": true,\n      \"strict_route\": true,\n      \"stack\": \"system\",\n      \"sniff\": true,\n      \"sniff_override_destination\": true\n    },\n    {\n      \"type\": \"mixed\",\n      \"tag\": \"mixed-in\",\n      \"listen\": \"127.0.0.1\",\n      \"listen_port\": 2080,\n      \"sniff\": true\n    }\n  ],\n  \"outbounds\": [\n    {\n      \"type\": \"selector\",\n      \"tag\": \"ArashProxy-Secure\",\n      \"outbounds\": [\n        \"Auto-Best-Edge\",\n        \"Cloudflare Edge Primary (VLESS + Fragment) (VLESS)\",\n        \"INCY Zero-Leak Tunnel (VLESS TLS) (VLESS)\",\n        \"Backup Anti-DPI (Trojan WS) (TROJAN)\",\n        \"Legacy Compatible (VMess TLS) (VMESS)\"\n      ],\n      \"default\": \"Auto-Best-Edge\"\n    },\n    {\n      \"type\": \"urltest\",\n      \"tag\": \"Auto-Best-Edge\",\n      \"outbounds\": [\n        \"Cloudflare Edge Primary (VLESS + Fragment) (VLESS)\",\n        \"INCY Zero-Leak Tunnel (VLESS TLS) (VLESS)\",\n        \"Backup Anti-DPI (Trojan WS) (TROJAN)\",\n        \"Legacy Compatible (VMess TLS) (VMESS)\"\n      ],\n      \"url\": \"https://www.gstatic.com/generate_204\",\n      \"interval\": \"3m\",\n      \"tolerance\": 50\n    },\n    {\n      \"type\": \"vless\",\n      \"tag\": \"Cloudflare Edge Primary (VLESS + Fragment) (VLESS)\",\n      \"server\": \"104.16.132.229\",\n      \"server_port\": 443,\n      \"uuid\": \"54aad0be-54d2-442e-9f4a-00f0bafe98ad\",\n      \"packet_encoding\": \"xudp\",\n      \"tls\": {\n        \"enabled\": true,\n        \"server_name\": \"Arashproxysystem.ir\",\n        \"utls\": {\n          \"enabled\": true,\n          \"fingerprint\": \"chrome\"\n        },\n        \"alpn\": [\n          \"http/1.1\"\n        ]\n      },\n      \"transport\": {\n        \"type\": \"ws\",\n        \"path\": \"/ws-5739ab8e?ed=2048\",\n        \"headers\": {\n          \"Host\": \"Arashproxysystem.ir\"\n        },\n        \"max_early_data\": 2048,\n        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"\n      }\n    },\n    {\n      \"type\": \"vless\",\n      \"tag\": \"INCY Zero-Leak Tunnel (VLESS TLS) (VLESS)\",\n      \"server\": \"172.64.155.141\",\n      \"server_port\": 2053,\n      \"uuid\": \"a9fbd798-2ed7-4042-825c-8db22dc6c428\",\n      \"packet_encoding\": \"xudp\",\n      \"tls\": {\n        \"enabled\": true,\n        \"server_name\": \"Arashproxysystem.ir\",\n        \"utls\": {\n          \"enabled\": true,\n          \"fingerprint\": \"safari\"\n        },\n        \"alpn\": [\n          \"http/1.1\"\n        ]\n      },\n      \"transport\": {\n        \"type\": \"ws\",\n        \"path\": \"/incy-d53b4e9f?ed=2048\",\n        \"headers\": {\n          \"Host\": \"Arashproxysystem.ir\"\n        },\n        \"max_early_data\": 2048,\n        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"\n      }\n    },\n    {\n      \"type\": \"trojan\",\n      \"tag\": \"Backup Anti-DPI (Trojan WS) (TROJAN)\",\n      \"server\": \"104.18.2.161\",\n      \"server_port\": 8443,\n      \"password\": \"KN1ApGK9_EgglIIbPkp54VE1\",\n      \"tls\": {\n        \"enabled\": true,\n        \"server_name\": \"Arashproxysystem.ir\",\n        \"utls\": {\n          \"enabled\": true,\n          \"fingerprint\": \"firefox\"\n        },\n        \"alpn\": [\n          \"http/1.1\"\n        ]\n      },\n      \"transport\": {\n        \"type\": \"ws\",\n        \"path\": \"/tr-46c1592a?ed=2048\",\n        \"headers\": {\n          \"Host\": \"Arashproxysystem.ir\"\n        },\n        \"max_early_data\": 2048,\n        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"\n      }\n    },\n    {\n      \"type\": \"vmess\",\n      \"tag\": \"Legacy Compatible (VMess TLS) (VMESS)\",\n      \"server\": \"162.159.135.42\",\n      \"server_port\": 443,\n      \"uuid\": \"409a0e9f-e72c-4f89-9ae3-45e5b43d3d84\",\n      \"security\": \"auto\",\n      \"alter_id\": 0,\n      \"tls\": {\n        \"enabled\": true,\n        \"server_name\": \"Arashproxysystem.ir\",\n        \"utls\": {\n          \"enabled\": true,\n          \"fingerprint\": \"chrome\"\n        },\n        \"alpn\": [\n          \"http/1.1\"\n        ]\n      },\n      \"transport\": {\n        \"type\": \"ws\",\n        \"path\": \"/vm-0699509b?ed=2048\",\n        \"headers\": {\n          \"Host\": \"Arashproxysystem.ir\"\n        },\n        \"max_early_data\": 2048,\n        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"\n      }\n    },\n    {\n      \"type\": \"direct\",\n      \"tag\": \"direct\"\n    },\n    {\n      \"type\": \"block\",\n      \"tag\": \"block\"\n    },\n    {\n      \"type\": \"dns\",\n      \"tag\": \"dns-out\"\n    }\n  ],\n  \"route\": {\n    \"rules\": [\n      {\n        \"protocol\": \"dns\",\n        \"outbound\": \"dns-out\"\n      },\n      {\n        \"protocol\": \"stun\",\n        \"outbound\": \"block\"\n      },\n      {\n        \"ip_is_private\": true,\n        \"outbound\": \"direct\"\n      }\n    ],\n    \"final\": \"ArashProxy-Secure\",\n    \"auto_detect_interface\": true\n  }\n}";
const PROXY_IP = '104.16.132.229';
const DOH_ENDPOINT = 'https://1.1.1.1/dns-query';
const STRICT_HEADER_STRIP = true;
const ANTI_PROBE_DECOY = true;

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get('Upgrade');

      // 1. Live Subscription Endpoint (/sub/:secret?format=v2ray|incy) backed by D1
      if (url.pathname.startsWith('/sub/')) {
        return await handleSubscriptionRequest(url, env);
      }

      // 2. Edge health check & D1 binding status
      if (url.pathname === '/health-edge') {
        let d1Ready = false;
        if (env && env.DB) {
          try {
            await env.DB.prepare('SELECT 1 AS ok').first();
            d1Ready = true;
          } catch {}
        }
        return new Response(
          JSON.stringify({ ok: true, edge: request.cf?.colo || 'CF', d1Bound: d1Ready }),
          {
            status: 200,
            headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
          }
        );
      }

      // 3. Return 405 JSON on /api/* so Edge Vault activates cleanly on Worker hosting
      if (url.pathname.startsWith('/api/')) {
        return new Response(JSON.stringify({ error: 'Edge vault mode' }), {
          status: 405,
          headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
        });
      }

      // 4. Non-WebSocket requests: pass through to Cloudflare Workers ASSETS or decoy
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        if (env && env.ASSETS) {
          return env.ASSETS.fetch(request);
        }
        return renderDecoyResponse(ANTI_PROBE_DECOY);
      }

      // 4. WebSocket VLESS tunnel: verify path & UUIDs (D1 first, fallback embedded)
      const { allowedUuids, allowedPaths } = await loadRuntimePolicy(env);
      const cleanPath = url.pathname.replace(/\/+$/, '') || '/';
      if (allowedPaths.size > 0 && !allowedPaths.has(cleanPath)) {
        return new Response('Not Found', { status: 404 });
      }

      const activeProxyIp = (env && env.PROXYIP) ? env.PROXYIP : PROXY_IP;
      return await handleVlessOverWS(request, activeProxyIp, allowedUuids);
    } catch (err) {
      return new Response('Bad Gateway', { status: 502 });
    }
  },
};

async function loadRuntimePolicy(env) {
  if (env && env.DB) {
    try {
      const { results } = await env.DB.prepare(
        "SELECT secret, path FROM proxy_tokens WHERE enabled = 1 AND protocol = 'vless'"
      ).all();
      if (results && results.length > 0) {
        return {
          allowedUuids: new Set(results.map((r) => r.secret)),
          allowedPaths: new Set(results.map((r) => r.path)),
        };
      }
    } catch {}
  }
  return { allowedUuids: FALLBACK_UUIDS, allowedPaths: FALLBACK_WS_PATHS };
}

async function handleSubscriptionRequest(url, env) {
  const providedSecret = url.pathname.slice('/sub/'.length).replace(/\/+$/, '');
  const format = (url.searchParams.get('format') || 'v2ray').toLowerCase();
  let expectedSecret = FALLBACK_SUB_SECRET;
  let d1Tokens = null;

  if (env && env.DB) {
    try {
      const settingsRow = await env.DB.prepare(
        'SELECT subscription_secret FROM proxy_settings WHERE id = 1'
      ).first();
      if (settingsRow && settingsRow.subscription_secret) {
        expectedSecret = settingsRow.subscription_secret;
      }
      const { results } = await env.DB.prepare(
        'SELECT * FROM proxy_tokens WHERE enabled = 1'
      ).all();
      if (results && results.length > 0) {
        d1Tokens = results;
      }
    } catch {}
  }

  if (!providedSecret || providedSecret !== expectedSecret) {
    return new Response('Not Found', { status: 404 });
  }

  const headers = {
    'Profile-Title': 'Arashproxysystem.ir',
    'Profile-Update-Interval': '6',
    'Cache-Control': 'no-store',
  };

  if (format === 'incy' || format === 'singbox') {
    return new Response(EMBEDDED_INCY_JSON, {
      status: 200,
      headers: { ...headers, 'content-type': 'application/json; charset=utf-8' },
    });
  }

  if (d1Tokens) {
    const lines = d1Tokens.map((t) => {
      const tag = encodeURIComponent(t.name + ' [ArashProxy]');
      const wsPath = encodeURIComponent(t.path + '?ed=2048');
      if (t.protocol === 'trojan') {
        return `trojan://${encodeURIComponent(t.secret)}@${t.clean_ip}:${t.port}?security=tls&sni=${encodeURIComponent(t.sni)}&fp=${t.fingerprint}&alpn=http%2F1.1&type=ws&host=${encodeURIComponent(t.host)}&path=${wsPath}#${tag}`;
      }
      return `vless://${t.secret}@${t.clean_ip}:${t.port}?encryption=none&security=tls&sni=${encodeURIComponent(t.sni)}&fp=${t.fingerprint}&alpn=http%2F1.1&type=ws&host=${encodeURIComponent(t.host)}&path=${wsPath}#${tag}`;
    });
    return new Response(btoa(unescape(encodeURIComponent(lines.join('\n')))), {
      status: 200,
      headers: { ...headers, 'content-type': 'text/plain; charset=utf-8' },
    });
  }

  return new Response(EMBEDDED_V2RAY_B64, {
    status: 200,
    headers: { ...headers, 'content-type': 'text/plain; charset=utf-8' },
  });
}

function renderDecoyResponse(enabled) {
  if (!enabled) {
    return new Response('404 Not Found', { status: 404 });
  }
  const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Arash Cloud Infrastructure</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}main{max-width:520px;padding:32px;border:1px solid #1e293b;border-radius:12px;background:#111827}</style>
</head>
<body><main><h1>Arashproxysystem.ir</h1><p>Static edge documentation node. No interactive endpoints are exposed on this path.</p></main></body></html>`;
  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-store',
    },
  });
}

async function handleVlessOverWS(request, proxyIp, allowedUuids) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let addressLog = '';
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = parseVlessHeader(chunk, allowedUuids);

          addressLog = addressRemote;
          if (hasError) {
            throw new Error('Invalid VLESS packet or unauthorized UUID');
          }

          // Block private/loopback SSRF targets on Worker edge
          if (isBlockedInternalAddress(addressRemote)) {
            throw new Error('Blocked internal address');
          }

          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
              const { write } = await handleUdpDnsOverHttps(webSocket, vlessResponseHeader);
              udpStreamWrite = write;
              udpStreamWrite(rawClientData);
              return;
            }
            throw new Error('Only DNS UDP port 53 is permitted for zero-leak protection');
          }

          await handleTcpOutbound(
            remoteSocketWrapper,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            proxyIp
          );
        },
        close() {},
        abort() {},
      })
    )
    .catch(() => {
      safeCloseWebSocket(webSocket);
    });

  const headers = new Headers();
  if (STRICT_HEADER_STRIP) {
    headers.set('Referrer-Policy', 'no-referrer');
    headers.set('X-Robots-Tag', 'noindex, nofollow');
  }

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers,
  });
}

function isBlockedInternalAddress(host) {
  const lower = host.toLowerCase();
  return (
    lower === 'localhost' ||
    lower.startsWith('127.') ||
    lower.startsWith('10.') ||
    lower.startsWith('192.168.') ||
    lower === '::1'
  );
}

function parseVlessHeader(vlessBuffer, allowedUuids) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const uuidBytes = new Uint8Array(vlessBuffer.slice(1, 17));
  const uuidStr = stringifyUuid(uuidBytes);

  if (!allowedUuids.has(uuidStr)) {
    return { hasError: true };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 19 + optLength))[0];
  let isUDP = false;
  if (command === 2) {
    isUDP = true;
  } else if (command !== 1) {
    return { hasError: true };
  }

  const portIndex = 19 + optLength;
  const portRemote = new DataView(vlessBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  if (addressType === 1) {
    addressLength = 4;
    addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
  } else if (addressType === 2) {
    addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
    addressValueIndex += 1;
    addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
  } else if (addressType === 3) {
    addressLength = 16;
    const dv = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
    const ipv6 = [];
    for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16));
    addressValue = ipv6.join(':');
  } else {
    return { hasError: true };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

function stringifyUuid(arr) {
  const hex = Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function handleTcpOutbound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, proxyIp) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retryViaProxyIp() {
    const tcpSocket = await connectAndWrite(proxyIp || addressRemote, portRemote);
    tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
    pipeRemoteToWebSocket(tcpSocket, webSocket, vlessResponseHeader, null);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  pipeRemoteToWebSocket(tcpSocket, webSocket, vlessResponseHeader, retryViaProxyIp);
}

async function pipeRemoteToWebSocket(remoteSocket, webSocket, vlessResponseHeader, retry) {
  let header = vlessResponseHeader;
  let hasIncomingData = false;

  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          hasIncomingData = true;
          if (webSocket.readyState !== 1) return;
          if (header) {
            const combined = new Uint8Array(header.length + chunk.byteLength);
            combined.set(header, 0);
            combined.set(new Uint8Array(chunk), header.length);
            webSocket.send(combined.buffer);
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {},
        abort() {},
      })
    )
    .catch(() => safeCloseWebSocket(webSocket));

  if (!hasIncomingData && retry) {
    await retry();
  }
}

async function handleUdpDnsOverHttps(webSocket, vlessResponseHeader) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let idx = 0; idx < chunk.byteLength; ) {
        const length = new DataView(chunk.slice(idx, idx + 2)).getUint16(0);
        controller.enqueue(new Uint8Array(chunk.slice(idx + 2, idx + 2 + length)));
        idx += 2 + length;
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(dnsQuery) {
          const resp = await fetch(DOH_ENDPOINT, {
            method: 'POST',
            headers: { 'content-type': 'application/dns-message' },
            body: dnsQuery,
          });
          const dnsBuffer = await resp.arrayBuffer();
          const lenBuf = new Uint8Array([(dnsBuffer.byteLength >> 8) & 0xff, dnsBuffer.byteLength & 0xff]);
          if (webSocket.readyState === 1) {
            const prefix = isHeaderSent ? new Uint8Array(0) : vlessResponseHeader;
            isHeaderSent = true;
            const payload = new Uint8Array(prefix.length + lenBuf.length + dnsBuffer.byteLength);
            payload.set(prefix, 0);
            payload.set(lenBuf, prefix.length);
            payload.set(new Uint8Array(dnsBuffer), prefix.length + lenBuf.length);
            webSocket.send(payload.buffer);
          }
        },
      })
    )
    .catch(() => {});

  const writer = transformStream.writable.getWriter();
  return { write: (chunk) => writer.write(chunk) };
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let cancelled = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (!cancelled) controller.enqueue(event.data);
      });
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (!cancelled) controller.close();
      });
      webSocketServer.addEventListener('error', (err) => controller.error(err));

      if (earlyDataHeader) {
        try {
          const decoded = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
          const bytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
          controller.enqueue(bytes.buffer);
        } catch {}
      }
    },
    cancel() {
      cancelled = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) socket.close();
  } catch {}
}
