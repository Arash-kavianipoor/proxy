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

export function buildRawUriList(tokens: ProxyToken[]): string {
  return tokens
    .filter((t) => t.enabled)
    .map(buildProxyUri)
    .join('\n');
}

export function buildV2RaySubscriptionPayload(tokens: ProxyToken[]): string {
  return toBase64Utf8(buildRawUriList(tokens));
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

export function buildWranglerToml(settings: SystemSettings): string {
  const dbId = settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae';
  return `name = "arash-proxy-system"
main = "worker/index.js"
compatibility_date = "2025-01-01"

[assets]
directory = "./dist"
binding = "ASSETS"
not_found_handling = "single-page-application"
run_worker_first = true

[vars]
PROXYIP = "${settings.proxyIp || '104.16.132.229'}"
PRIMARY_DOMAIN = "${settings.domain}"

[[d1_databases]]
binding = "DB"
database_name = "arashproxydb"
database_id = "${dbId}"
`;
}

export function buildD1SchemaSql(tokens: ProxyToken[], settings: SystemSettings): string {
  const esc = (s: string) => s.replace(/'/g, "''");
  const tokenInserts = tokens
    .map(
      (t) =>
        `INSERT OR REPLACE INTO proxy_tokens (id, name, protocol, secret, clean_ip, port, sni, host, path, transport, fingerprint, tls_fragment_enabled, enabled, updated_at) VALUES ('${esc(t.id)}', '${esc(t.name)}', '${esc(t.protocol)}', '${esc(t.secret)}', '${esc(t.cleanIp)}', ${t.port}, '${esc(t.sni)}', '${esc(t.host)}', '${esc(t.path)}', '${esc(t.transport)}', '${esc(t.fingerprint)}', ${t.tlsFragmentEnabled ? 1 : 0}, ${t.enabled ? 1 : 0}, '${esc(t.lastRotatedAt)}');`
    )
    .join('\n');

  return `-- Cloudflare D1 Schema for ${settings.domain} (Database ID: ${settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae'})
CREATE TABLE IF NOT EXISTS proxy_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  domain TEXT NOT NULL,
  proxy_ip TEXT NOT NULL,
  doh_provider TEXT NOT NULL,
  subscription_secret TEXT NOT NULL,
  strip_client_headers INTEGER NOT NULL DEFAULT 1,
  anti_probe_decoy INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  secret TEXT NOT NULL,
  clean_ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  sni TEXT NOT NULL,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  transport TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  tls_fragment_enabled INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);

INSERT OR REPLACE INTO proxy_settings (id, domain, proxy_ip, doh_provider, subscription_secret, strip_client_headers, anti_probe_decoy, updated_at)
VALUES (1, '${esc(settings.domain)}', '${esc(settings.proxyIp)}', '${esc(settings.dohProvider)}', '${esc(settings.subscriptionSecret)}', ${settings.stripClientHeaders ? 1 : 0}, ${settings.antiProbeDecoy ? 1 : 0}, '${new Date().toISOString()}');

${tokenInserts}
`;
}

export function buildCloudflareWorkerScript(tokens: ProxyToken[], settings: SystemSettings): string {
  const activeTokens = tokens.filter((t) => t.enabled);
  const vlessUuids = activeTokens.filter((t) => t.protocol === 'vless').map((t) => t.secret);
  const primaryUuid = vlessUuids[0] || tokens[0]?.secret || 'd342d11e-d424-4583-b36e-524ab1f0afa4';
  const allowedPaths = Array.from(new Set(activeTokens.map((t) => t.path)));
  const embeddedV2RayBase64 = buildV2RaySubscriptionPayload(tokens);
  const embeddedIncyJson = buildIncySingBoxConfig(tokens, settings);

  return `// Cloudflare Pages / Worker for ${settings.domain}
// Connected to Cloudflare D1 (${settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae'})
// Supports: VLESS over WebSocket + /sub/:secret (V2Ray & INCY) + ProxyIP Relay + Anti-Probe
import { connect } from 'cloudflare:sockets';

const FALLBACK_UUIDS = new Set(${JSON.stringify(vlessUuids.length > 0 ? vlessUuids : [primaryUuid])});
const FALLBACK_WS_PATHS = new Set(${JSON.stringify(allowedPaths.length > 0 ? allowedPaths : ['/ws-arash'])});
const FALLBACK_SUB_SECRET = '${settings.subscriptionSecret}';
const EMBEDDED_V2RAY_B64 = '${embeddedV2RayBase64}';
const EMBEDDED_INCY_JSON = ${JSON.stringify(embeddedIncyJson)};
const PROXY_IP = '${settings.proxyIp || '104.16.132.229'}';
const DOH_ENDPOINT = '${settings.dohProvider || 'https://1.1.1.1/dns-query'}';
const STRICT_HEADER_STRIP = ${settings.stripClientHeaders ? 'true' : 'false'};
const ANTI_PROBE_DECOY = ${settings.antiProbeDecoy ? 'true' : 'false'};

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
      const cleanPath = url.pathname.replace(/\\/+$/, '') || '/';
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
  const providedSecret = url.pathname.slice('/sub/'.length).replace(/\\/+$/, '');
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
    'Profile-Title': '${settings.domain}',
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
        return \`trojan://\${encodeURIComponent(t.secret)}@\${t.clean_ip}:\${t.port}?security=tls&sni=\${encodeURIComponent(t.sni)}&fp=\${t.fingerprint}&alpn=http%2F1.1&type=ws&host=\${encodeURIComponent(t.host)}&path=\${wsPath}#\${tag}\`;
      }
      return \`vless://\${t.secret}@\${t.clean_ip}:\${t.port}?encryption=none&security=tls&sni=\${encodeURIComponent(t.sni)}&fp=\${t.fingerprint}&alpn=http%2F1.1&type=ws&host=\${encodeURIComponent(t.host)}&path=\${wsPath}#\${tag}\`;
    });
    return new Response(btoa(unescape(encodeURIComponent(lines.join('\\n')))), {
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
