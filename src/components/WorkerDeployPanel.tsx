import { useEffect, useState } from 'react';
import { Check, Copy, Download, RefreshCw } from 'lucide-react';
import { fetchWorkerScript } from '../lib/api.ts';
import { buildCloudflareWorkerScript } from '../lib/proxyGenerators.ts';
import type { DashboardState } from '../types.ts';

interface WorkerDeployPanelProps {
  dashboard: DashboardState;
  onUpdate: (next: DashboardState) => void;
}

export function WorkerDeployPanel({ dashboard, onUpdate }: WorkerDeployPanelProps) {
  const [script, setScript] = useState(() =>
    buildCloudflareWorkerScript(dashboard.tokens, dashboard.settings)
  );
  const [copied, setCopied] = useState(false);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    setScript(buildCloudflareWorkerScript(dashboard.tokens, dashboard.settings));
  }, [dashboard.tokens, dashboard.settings]);

  const handleSyncFromServer = async () => {
    setSyncing(true);
    try {
      const res = await fetchWorkerScript();
      setScript(res.script);
      onUpdate(res.dashboard);
    } finally {
      setSyncing(false);
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(script);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Ignore
    }
  };

  const handleDownload = () => {
    const blob = new Blob([script], { type: 'application/javascript;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '_worker.js';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Deployment Guide for Arashproxysystem.ir */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <h2 className="text-base font-semibold text-[#E6EDF3]">
          راه‌اندازی ورکر کلودفلر روی دامنه{' '}
          <span dir="ltr" className="font-mono text-emerald-400">
            {dashboard.settings.domain}
          </span>
        </h2>
        <p className="mt-1.5 text-xs leading-6 text-[#94A3B8]">
          این ورکر تمام درخواست‌های VLESS over WebSocket را در لبه کلودفلر دریافت کرده، هدرهای افشاگر آی‌پی ایران را حذف می‌کند و ترافیک را از طریق{' '}
          <span dir="ltr" className="font-mono text-[#CBD5E1]">
            PROXYIP ({dashboard.settings.proxyIp})
          </span>{' '}
          یا شبکه جهانی کلودفلر عبور می‌دهد.
        </p>

        <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-4">
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="font-mono text-xs font-semibold text-emerald-400">01</div>
            <div className="mt-2 text-xs font-semibold text-[#E6EDF3]">ایجاد Worker در کلودفلر</div>
            <p className="mt-1.5 text-xs leading-5 text-[#94A3B8]">
              در پنل Cloudflare بخش Workers &amp; Pages یک Worker جدید بسازید و کد زیر را جایگزین کنید.
            </p>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="font-mono text-xs font-semibold text-emerald-400">02</div>
            <div className="mt-2 text-xs font-semibold text-[#E6EDF3]">اتصال دامنه شخصی</div>
            <p className="mt-1.5 text-xs leading-5 text-[#94A3B8]">
              در تب Settings &gt; Domains &amp; Routes دامنه{' '}
              <span dir="ltr" className="font-mono text-[#CBD5E1]">
                {dashboard.settings.domain}
              </span>{' '}
              را متصل کنید (ایران workers.dev را فیلتر کرده؛ دامنه شخصی الزامی است).
            </p>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="font-mono text-xs font-semibold text-emerald-400">03</div>
            <div className="mt-2 text-xs font-semibold text-[#E6EDF3]">تنظیم متغیر PROXYIP</div>
            <p className="mt-1.5 text-xs leading-5 text-[#94A3B8]">
              در Variables متغیر <span className="font-mono text-[#CBD5E1]">PROXYIP</span> را با{' '}
              <span dir="ltr" className="font-mono text-[#CBD5E1]">
                {dashboard.settings.proxyIp}
              </span>{' '}
              ثبت کنید تا سایت‌های پشت کلودفلر هم بدون خطا باز شوند.
            </p>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="font-mono text-xs font-semibold text-emerald-400">04</div>
            <div className="mt-2 text-xs font-semibold text-[#E6EDF3]">فعال‌سازی TLS 1.3 و WS</div>
            <p className="mt-1.5 text-xs leading-5 text-[#94A3B8]">
              در بخش SSL/TLS گزینه Full (Strict) و در Network گزینه‌های WebSockets و TLS 1.3 را روشن نگه دارید.
            </p>
          </div>
        </div>
      </section>

      {/* Worker Source Code */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-[#E6EDF3]">
              کد نهایی ورکر کلودفلر (<span className="font-mono">_worker.js</span>)
            </h3>
            <p className="mt-1 text-xs text-[#94A3B8]">
              شامل {dashboard.tokens.filter((t) => t.enabled && t.protocol === 'vless').length} شناسه UUID مجاز، مسیرهای WebSocket تصادفی، DoH داخلی و صفحه فریب ضداسکن.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleSyncFromServer}
              disabled={syncing}
              className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${syncing ? 'animate-spin' : ''}`} />
              <span>همگام‌سازی و ثبت در گزارش</span>
            </button>
            <button
              type="button"
              onClick={handleDownload}
              className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" />
              <span>دانلود _worker.js</span>
            </button>
            <button
              type="button"
              onClick={handleCopy}
              className="flex h-9 items-center gap-1.5 rounded-lg bg-emerald-600 px-4 text-xs font-medium text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? 'کپی شد' : 'کپی کد ورکر'}</span>
            </button>
          </div>
        </div>

        <pre
          dir="ltr"
          className="mt-4 max-h-[520px] overflow-auto rounded-lg border border-[#1E293B] bg-[#090D14] p-4 font-mono text-xs leading-6 text-[#CBD5E1]"
        >
          <code>{script}</code>
        </pre>
      </section>
    </div>
  );
}
