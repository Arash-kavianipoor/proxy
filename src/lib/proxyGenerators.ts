import type { ProxyToken, SystemSettings } from '../types.ts';

function toBase64Utf8(str: string): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'utf8').toString('base64');
  }
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function buildProxyUri(token: ProxyToken): string {
  const tag = encodeURIComponent(`${token.name} [ArashProxy]`);
  const wsPath = encodeURIComponent(`${token.path}?ed=2048`);

  if (token.protocol === 'vless') {
    if (token.transport === 'grpc') {
      const serviceName = encodeURIComponent(token.path.replace(/^\//, ''));
      return `vless://${token.secret}@${token.cleanIp}:${token.port}?encryption=none&security=tls&sni=${encodeURIComponent(token.sni)}&fp=${token.fingerprint}&alpn=h2&type=grpc&serviceName=${serviceName}&mode=gun#${tag}`;
    }
    return `vless://${token.secret}@${token.cleanIp}:${token.port}?encryption=none&security=tls&sni=${encodeURIComponent(token.sni)}&fp=${token.fingerprint}&alpn=http%2F1.1&type=ws&host=${encodeURIComponent(token.host)}&path=${wsPath}#${tag}`;
  }

  if (token.protocol === 'trojan') {
    return `trojan://${encodeURIComponent(token.secret)}@${token.cleanIp}:${token.port}?security=tls&sni=${encodeURIComponent(token.sni)}&fp=${token.fingerprint}&alpn=http%2F1.1&type=ws&host=${encodeURIComponent(token.host)}&path=${wsPath}#${tag}`;
  }

  // VMess JSON v2 URI
  const vmessConfig = {
    v: '2',
    ps: `${token.name} [ArashProxy]`,
    add: token.cleanIp,
    port: String(token.port),
    id: token.secret,
    aid: '0',
    scy: 'auto',
    net: token.transport,
    type: 'none',
    host: token.host,
    path: `${token.path}?ed=2048`,
    tls: 'tls',
    sni: token.sni,
    alpn: 'http/1.1',
    fp: token.fingerprint,
  };
  return `vmess://${toBase64Utf8(JSON.stringify(vmessConfig))}`;
}

export function buildV2RaySubscriptionPayload(tokens: ProxyToken[]): string {
  const active = tokens.filter((t) => t.enabled);
  const uris = active.map(buildProxyUri).join('\n');
  return toBase64Utf8(uris);
}

export function buildIncySingBoxConfig(tokens: ProxyToken[], settings: SystemSettings): string {
  const activeTokens = tokens.filter((t) => t.enabled);
  const outbounds: Record<string, unknown>[] = [];
  const selectorTags: string[] = [];

  for (const token of activeTokens) {
    const tag = `${token.name} (${token.protocol.toUpperCase()})`;
    selectorTags.push(tag);

    const tlsConfig: Record<string, unknown> = {
      enabled: true,
      server_name: token.sni,
      utls: {
        enabled: true,
        fingerprint: token.fingerprint === 'random' ? 'chrome' : token.fingerprint,
      },
      alpn: token.transport === 'grpc' ? ['h2'] : ['http/1.1'],
    };

    const transportConfig: Record<string, unknown> =
      token.transport === 'grpc'
        ? {
            type: 'grpc',
            service_name: token.path.replace(/^\//, ''),
          }
        : {
            type: 'ws',
            path: `${token.path}?ed=2048`,
            headers: {
              Host: token.host,
            },
            max_early_data: 2048,
            early_data_header_name: 'Sec-WebSocket-Protocol',
          };

    if (token.protocol === 'vless') {
      outbounds.push({
        type: 'vless',
        tag,
        server: token.cleanIp,
        server_port: token.port,
        uuid: token.secret,
        packet_encoding: 'xudp',
        tls: tlsConfig,
        transport: transportConfig,
      });
    } else if (token.protocol === 'trojan') {
      outbounds.push({
        type: 'trojan',
        tag,
        server: token.cleanIp,
        server_port: token.port,
        password: token.secret,
        tls: tlsConfig,
        transport: transportConfig,
      });
    } else {
      outbounds.push({
        type: 'vmess',
        tag,
        server: token.cleanIp,
        server_port: token.port,
        uuid: token.secret,
        security: 'auto',
        alter_id: 0,
        tls: tlsConfig,
        transport: transportConfig,
      });
    }
  }

  const autoTag = 'Auto-Best-Edge';
  const proxyTag = 'ArashProxy-Secure';

  const config = {
    log: {
      level: 'warn',
      timestamp: true,
    },
    dns: {
      servers: [
        {
          tag: 'doh-remote',
          address: settings.dohProvider || 'https://1.1.1.1/dns-query',
          address_resolver: 'dns-bootstrap',
          detour: proxyTag,
          strategy: 'ipv4_only',
        },
        {
          tag: 'dns-bootstrap',
          address: '1.1.1.1',
          detour: 'direct',
        },
        {
          tag: 'dns-block',
          address: 'rcode://success',
        },
      ],
      rules: [
        {
          outbound: 'any',
          server: 'dns-bootstrap',
        },
        {
          protocol: 'stun',
          server: 'dns-block',
        },
      ],
      final: 'doh-remote',
      independent_cache: true,
    },
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        inet4_address: '172.19.0.1/30',
        mtu: 1400,
        auto_route: true,
        strict_route: true,
        stack: 'system',
        sniff: true,
        sniff_override_destination: true,
      },
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: 2080,
        sniff: true,
      },
    ],
    outbounds: [
      {
        type: 'selector',
        tag: proxyTag,
        outbounds: selectorTags.length > 0 ? [autoTag, ...selectorTags] : ['direct'],
        default: selectorTags.length > 0 ? autoTag : 'direct',
      },
      ...(selectorTags.length > 0
        ? [
            {
              type: 'urltest',
              tag: autoTag,
              outbounds: selectorTags,
              url: 'https://www.gstatic.com/generate_204',
              interval: '3m',
              tolerance: 50,
            },
          ]
        : []),
      ...outbounds,
      {
        type: 'direct',
        tag: 'direct',
      },
      {
        type: 'block',
        tag: 'block',
      },
      {
        type: 'dns',
        tag: 'dns-out',
      },
    ],
    route: {
      rules: [
        {
          protocol: 'dns',
          outbound: 'dns-out',
        },
        ...(settings.webrtcBlock
          ? [
              {
                protocol: 'stun',
                outbound: 'block',
              },
            ]
          : []),
        {
          ip_is_private: true,
          outbound: 'direct',
        },
      ],
      final: proxyTag,
      auto_detect_interface: true,
    },
  };

  return JSON.stringify(config, null, 2);
}

export function buildXrayFragmentConfig(token: ProxyToken, settings: SystemSettings): string {
  const fragmentOutbound = {
    tag: 'fragment',
    protocol: 'freedom',
    settings: {
      domainStrategy: 'AsIs',
      fragment: {
        packets: 'tlshello',
        length: token.fragmentLength || '10-20',
        interval: token.fragmentInterval || '10-20',
      },
    },
    streamSettings: {
      sockopt: {
        tcpKeepAliveIdle: 100,
        tcpNoDelay: true,
      },
    },
  };

  const proxyOutbound: Record<string, unknown> = {
    tag: 'proxy',
    protocol: token.protocol,
    settings:
      token.protocol === 'vless'
        ? {
            vnext: [
              {
                address: token.cleanIp,
                port: token.port,
                users: [
                  {
                    id: token.secret,
                    encryption: 'none',
                  },
                ],
              },
            ],
          }
        : token.protocol === 'trojan'
          ? {
              servers: [
                {
                  address: token.cleanIp,
                  port: token.port,
                  password: token.secret,
                },
              ],
            }
          : {
              vnext: [
                {
                  address: token.cleanIp,
                  port: token.port,
                  users: [
                    {
                      id: token.secret,
                      alterId: 0,
                      security: 'auto',
                    },
                  ],
                },
              ],
            },
    streamSettings: {
      network: token.transport,
      security: 'tls',
      tlsSettings: {
        serverName: token.sni,
        allowInsecure: false,
        fingerprint: token.fingerprint === 'random' ? 'chrome' : token.fingerprint,
        alpn: token.transport === 'grpc' ? ['h2'] : ['http/1.1'],
      },
      ...(token.transport === 'ws'
        ? {
            wsSettings: {
              path: `${token.path}?ed=2048`,
              headers: {
                Host: token.host,
              },
            },
          }
        : {
            grpcSettings: {
              serviceName: token.path.replace(/^\//, ''),
              multiMode: false,
            },
          }),
      ...(token.tlsFragmentEnabled
        ? {
            sockopt: {
              dialerProxy: 'fragment',
              tcpKeepAliveIdle: 100,
              tcpNoDelay: true,
            },
          }
        : {}),
    },
  };

  const config = {
    remarks: `${token.name} - ${settings.domain} (Anti-DPI + Zero-IP-Leak)`,
    dns: {
      hosts: {
        'dns.google': '8.8.8.8',
      },
      servers: [
        {
          address: settings.dohProvider || 'https+local://1.1.1.1/dns-query',
        },
      ],
    },
    inbounds: [
      {
        tag: 'socks',
        port: 10808,
        listen: '127.0.0.1',
        protocol: 'socks',
        sniffing: {
          enabled: true,
          destOverride: ['http', 'tls', 'quic'],
          routeOnly: false,
        },
        settings: {
          auth: 'noauth',
          udp: true,
        },
      },
      {
        tag: 'http',
        port: 10809,
        listen: '127.0.0.1',
        protocol: 'http',
        sniffing: {
          enabled: true,
          destOverride: ['http', 'tls'],
        },
      },
    ],
    outbounds: [
      proxyOutbound,
      ...(token.tlsFragmentEnabled ? [fragmentOutbound] : []),
      {
        tag: 'direct',
        protocol: 'freedom',
      },
      {
        tag: 'block',
        protocol: 'blackhole',
      },
    ],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        ...(settings.webrtcBlock
          ? [
              {
                type: 'field',
                protocol: ['bittorrent'],
                outboundTag: 'block',
              },
              {
                type: 'field',
                port: '3478,19302',
                network: 'udp',
                outboundTag: 'block',
              },
            ]
          : []),
        {
          type: 'field',
          ip: ['geoip:private'],
          outboundTag: 'direct',
        },
        {
          type: 'field',
          network: 'tcp,udp',
          outboundTag: 'proxy',
        },
      ],
    },
  };

  return JSON.stringify(config, null, 2);
}

export function buildCloudflareWorkerScript(tokens: ProxyToken[], settings: SystemSettings): string {
  const vlessUuids = tokens
    .filter((t) => t.enabled && t.protocol === 'vless')
    .map((t) => t.secret);
  const primaryUuid = vlessUuids[0] || tokens[0]?.secret || 'd342d11e-d424-4583-b36e-524ab1f0afa4';
  const allowedPaths = Array.from(new Set(tokens.filter((t) => t.enabled).map((t) => t.path)));

  return `// Cloudflare Worker for ${settings.domain}
// Zero-IP-Leak VLESS over WebSocket + ProxyIP Relay + Anti-Probe Decoy
import { connect } from 'cloudflare:sockets';

const ALLOWED_UUIDS = new Set(${JSON.stringify(vlessUuids.length > 0 ? vlessUuids : [primaryUuid])});
const ALLOWED_WS_PATHS = new Set(${JSON.stringify(allowedPaths.length > 0 ? allowedPaths : ['/ws-arash'])});
const PROXY_IP = '${settings.proxyIp || '104.16.132.229'}';
const DOH_ENDPOINT = '${settings.dohProvider || 'https://1.1.1.1/dns-query'}';
const STRICT_HEADER_STRIP = ${settings.stripClientHeaders ? 'true' : 'false'};
const ANTI_PROBE_DECOY = ${settings.antiProbeDecoy ? 'true' : 'false'};

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get('Upgrade');

      // 1. Non-WebSocket requests get a clean anti-probe decoy website
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        if (url.pathname === '/health-edge') {
          return new Response(JSON.stringify({ ok: true, edge: request.cf?.colo || 'CF' }), {
            status: 200,
            headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
          });
        }
        return renderDecoyResponse(ANTI_PROBE_DECOY);
      }

      // 2. Enforce randomized WebSocket path to stop active port/path scanning
      const cleanPath = url.pathname.replace(/\\/+$/, '') || '/';
      if (ALLOWED_WS_PATHS.size > 0 && !ALLOWED_WS_PATHS.has(cleanPath)) {
        return new Response('Not Found', { status: 404 });
      }

      const activeProxyIp = (env && env.PROXYIP) ? env.PROXYIP : PROXY_IP;
      return await handleVlessOverWS(request, activeProxyIp);
    } catch (err) {
      return new Response('Bad Gateway', { status: 502 });
    }
  },
};

function renderDecoyResponse(enabled) {
  if (!enabled) {
    return new Response('404 Not Found', { status: 404 });
  }
  const html = \`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${settings.decoyTitle || 'Arash Cloud Infrastructure'}</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}main{max-width:520px;padding:32px;border:1px solid #1e293b;border-radius:12px;background:#111827}</style>
</head>
<body><main><h1>${settings.domain}</h1><p>Static edge documentation node. No interactive endpoints are exposed on this path.</p></main></body></html>\`;
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

async function handleVlessOverWS(request, proxyIp) {
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
          } = parseVlessHeader(chunk);

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

function parseVlessHeader(vlessBuffer) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const uuidBytes = new Uint8Array(vlessBuffer.slice(1, 17));
  const uuidStr = stringifyUuid(uuidBytes);

  if (!ALLOWED_UUIDS.has(uuidStr)) {
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
  return \`\${hex.slice(0, 8)}-\${hex.slice(8, 12)}-\${hex.slice(12, 16)}-\${hex.slice(16, 20)}-\${hex.slice(20)}\`;
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
`;
}
