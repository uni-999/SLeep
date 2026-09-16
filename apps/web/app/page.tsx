'use client';

import { useMemo, useState } from 'react';
import {
  Activity,
  Box,
  Check,
  ChevronDown,
  CircleDot,
  Clock3,
  Filter,
  Globe2,
  ListFilter,
  Network,
  PackageCheck,
  Play,
  RefreshCw,
  Search,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  TerminalSquare,
  UserRound,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

type Severity = 'critical' | 'high' | 'medium' | 'low';
type DeviceStatus = 'online' | 'degraded' | 'offline';

type Device = {
  id: string;
  name: string;
  platform: string;
  role: string;
  address: string;
  status: DeviceStatus;
  cves: number;
  critical: number;
  risk: number;
  lastSeen: string;
};

type CveFinding = {
  id: string;
  title: string;
  component: string;
  installed: string;
  fixed: string;
  severity: Severity;
  score: number;
  epss: string;
  exposure: string;
  confidence: string;
  evidence: string[];
  action: string;
};

type SecurityEvent = {
  id: string;
  title: string;
  type: 'auth' | 'process' | 'network' | 'package' | 'service';
  severity: 'high' | 'medium' | 'low' | 'info';
  time: string;
  period: string;
  records: number;
  summary: string;
  actor: string;
};

const devices: Device[] = [
  { id: 'prod-web-01', name: 'prod-web-01', platform: 'Ubuntu 22.04', role: 'Веб-приложение', address: '10.24.3.18', status: 'online', cves: 14, critical: 2, risk: 78, lastSeen: '18 сек назад' },
  { id: 'auth-api-02', name: 'auth-api-02', platform: 'RHEL 9.4', role: 'API авторизации', address: '10.24.4.11', status: 'degraded', cves: 8, critical: 1, risk: 64, lastSeen: '2 мин назад' },
  { id: 'finance-db-01', name: 'finance-db-01', platform: 'Windows Server 2022', role: 'База данных', address: '10.24.8.4', status: 'online', cves: 5, critical: 0, risk: 41, lastSeen: '31 сек назад' },
  { id: 'worker-legacy-03', name: 'worker-legacy-03', platform: 'Debian 11', role: 'Фоновая обработка', address: '10.24.7.23', status: 'offline', cves: 21, critical: 3, risk: 86, lastSeen: '4 ч назад' },
];

const cves: CveFinding[] = [
  {
    id: 'CVE-2024-6387', title: 'Race condition в OpenSSH server', component: 'openssh-server',
    installed: '1:8.9p1-3ubuntu0.7', fixed: '1:8.9p1-3ubuntu0.10', severity: 'critical', score: 8.1,
    epss: '0.94%', exposure: 'Доступен из внешнего сегмента', confidence: 'Высокая · 96%',
    evidence: ['sshd запущен от root', 'TCP/22 доступен через edge-firewall', 'Версия пакета ниже исправленной'],
    action: 'Обновить openssh-server и перезапустить sshd в согласованное окно.',
  },
  {
    id: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset', component: 'nginx',
    installed: '1.18.0-6ubuntu14.4', fixed: 'Обновление конфигурации и пакета', severity: 'high', score: 7.5,
    epss: '2.31%', exposure: 'Публичный HTTPS endpoint', confidence: 'Средняя · 82%',
    evidence: ['HTTP/2 включён на :443', 'Nginx принимает публичный трафик', 'Rate limit для reset-потока не обнаружен'],
    action: 'Обновить Nginx и проверить лимиты одновременных HTTP/2 streams.',
  },
  {
    id: 'CVE-2023-38545', title: 'Heap overflow в SOCKS5 обработчике curl', component: 'libcurl4',
    installed: '7.81.0-1ubuntu1.13', fixed: '7.81.0-1ubuntu1.15', severity: 'high', score: 8.8,
    epss: '0.37%', exposure: 'Локальная библиотека', confidence: 'Высокая · 91%',
    evidence: ['Уязвимая библиотека загружена worker-процессом', 'Процесс выполняет исходящие HTTP-запросы'],
    action: 'Обновить libcurl4 после проверки совместимости worker-процесса.',
  },
  {
    id: 'CVE-2024-10979', title: 'Некорректная обработка переменных окружения', component: 'postgresql-client-14',
    installed: '14.11-0ubuntu0.22.04.1', fixed: '14.13 или новее', severity: 'medium', score: 6.4,
    epss: '0.05%', exposure: 'Только локальное использование', confidence: 'Средняя · 74%',
    evidence: ['Клиент установлен', 'Активный уязвимый процесс не обнаружен'],
    action: 'Включить обновление в ближайшее плановое окно.',
  },
];

const events: SecurityEvent[] = [
  { id: 'evt-01842', title: 'Серия неуспешных SSH-входов', type: 'auth', severity: 'high', time: '10:42', period: '10:39:12–10:42:08', records: 487, summary: 'Попытки входа под root и deploy с одного внешнего адреса.', actor: '185.17.42.91' },
  { id: 'evt-01839', title: 'Изменена конфигурация Nginx', type: 'service', severity: 'medium', time: '10:31', period: '10:31:04–10:31:19', records: 6, summary: 'Изменён server block, после проверки конфигурации выполнен reload.', actor: 'deploy' },
  { id: 'evt-01828', title: 'Новый исходящий сетевой адрес', type: 'network', severity: 'medium', time: '09:54', period: '09:54:22–09:55:02', records: 12, summary: 'Worker-процесс впервые обратился к адресу вне известных подсетей.', actor: 'python3 · worker.service' },
  { id: 'evt-01812', title: 'Обновлены системные пакеты', type: 'package', severity: 'info', time: '08:16', period: '08:16:08–08:18:44', records: 28, summary: 'Обновлены 9 пакетов, 2 изменения повлияли на CVE-снимок.', actor: 'unattended-upgrades' },
  { id: 'evt-01798', title: 'Перезапущен PostgreSQL client worker', type: 'process', severity: 'low', time: '07:41', period: '07:41:01–07:41:06', records: 4, summary: 'Процесс штатно перезапущен после доставки новой версии приложения.', actor: 'systemd' },
];

const severityStyles: Record<Severity, string> = {
  critical: 'bg-red-50 text-red-700 ring-red-200',
  high: 'bg-orange-50 text-orange-700 ring-orange-200',
  medium: 'bg-amber-50 text-amber-800 ring-amber-200',
  low: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
};

const severityLabels: Record<Severity, string> = {
  critical: 'Критическая', high: 'Высокая', medium: 'Средняя', low: 'Низкая',
};

const eventIcons = { auth: UserRound, process: TerminalSquare, network: Network, package: PackageCheck, service: Settings2 };
const eventTone = {
  high: 'bg-red-50 text-red-700 ring-red-200',
  medium: 'bg-amber-50 text-amber-800 ring-amber-200',
  low: 'bg-sky-50 text-sky-700 ring-sky-200',
  info: 'bg-zinc-100 text-zinc-600 ring-zinc-200',
};

function StatusDot({ status }: { status: DeviceStatus }) {
  return <span className={cn('size-2 shrink-0 rounded-full ring-2 ring-white', status === 'online' && 'bg-emerald-500', status === 'degraded' && 'bg-amber-500', status === 'offline' && 'bg-zinc-400')} />;
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="min-w-0 px-4 py-3 first:pl-0 sm:px-6">
      <p className="text-[11px] font-medium text-zinc-500">{label}</p>
      <p className={cn('mt-1 truncate text-lg font-semibold tabular-nums text-zinc-950', tone)}>{value}</p>
    </div>
  );
}

function AppLogo() {
  return (
    <div className="flex items-center gap-2.5">
      <span className="grid size-8 place-items-center rounded-md bg-[#12382e] text-white"><Shield className="size-4" strokeWidth={2.25} /></span>
      <div><p className="text-sm font-semibold leading-none text-zinc-950">SLeep</p><p className="mt-1 text-[10px] leading-none text-zinc-500">Security posture</p></div>
    </div>
  );
}

export default function Home() {
  const [deviceId, setDeviceId] = useState(devices[0].id);
  const [activeTab, setActiveTab] = useState('cve');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<'all' | Severity>('all');
  const [selectedCveId, setSelectedCveId] = useState(cves[0].id);
  const [probeState, setProbeState] = useState<'idle' | 'queued'>('idle');

  const device = devices.find((item) => item.id === deviceId) ?? devices[0];
  const selectedCve = cves.find((item) => item.id === selectedCveId) ?? cves[0];
  const filteredCves = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return cves.filter((item) => (severity === 'all' || item.severity === severity) && (!normalized || item.id.toLowerCase().includes(normalized) || item.component.toLowerCase().includes(normalized) || item.title.toLowerCase().includes(normalized)));
  }, [query, severity]);

  function queueProbe() {
    setProbeState('queued');
    window.setTimeout(() => setProbeState('idle'), 3200);
  }

  return (
    <TooltipProvider>
      <div className="min-h-screen bg-[#f4f6f5] text-zinc-900">
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-zinc-200 bg-white px-4 sm:px-6">
          <AppLogo />
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="hidden rounded-md border-zinc-200 text-zinc-600 sm:flex">Demo organization</Badge>
            <Tooltip>
              <TooltipTrigger render={<Button variant="ghost" size="icon" aria-label="Уведомления" />}><CircleDot className="size-4 text-zinc-600" /></TooltipTrigger>
              <TooltipContent>Уведомления</TooltipContent>
            </Tooltip>
            <button className="grid size-8 place-items-center rounded-full bg-[#e7efe9] text-xs font-semibold text-[#12382e]" aria-label="Профиль пользователя">ES</button>
          </div>
        </header>

        <div className="mx-auto grid min-h-[calc(100vh-56px)] max-w-[1600px] grid-cols-1 lg:grid-cols-[232px_minmax(0,1fr)]">
          <aside className="border-b border-zinc-200 bg-[#eef1ef] lg:border-b-0 lg:border-r">
            <div className="flex items-center justify-between px-4 pb-2 pt-4">
              <p className="text-xs font-semibold text-zinc-700">Устройства</p>
              <Badge variant="secondary" className="rounded-md bg-white text-zinc-600">4</Badge>
            </div>
            <div className="hidden space-y-1 px-2 pb-5 lg:block">
              {devices.map((item) => (
                <button key={item.id} onClick={() => setDeviceId(item.id)} className={cn('flex w-full items-start gap-2.5 rounded-md px-2.5 py-2.5 text-left transition-colors', item.id === device.id ? 'bg-white shadow-[0_1px_2px_rgb(0_0_0/6%)]' : 'hover:bg-white/60')}>
                  <StatusDot status={item.status} />
                  <span className="min-w-0 flex-1"><span className="block truncate text-xs font-semibold text-zinc-900">{item.name}</span><span className="mt-1 block truncate text-[11px] text-zinc-500">{item.platform}</span></span>
                  {item.critical > 0 && <span className="min-w-5 rounded bg-red-50 px-1.5 py-0.5 text-center text-[10px] font-semibold text-red-700">{item.critical}</span>}
                </button>
              ))}
            </div>
            <div className="px-4 pb-4 lg:hidden">
              <label className="sr-only" htmlFor="mobile-device">Выбрать устройство</label>
              <div className="relative">
                <select id="mobile-device" value={deviceId} onChange={(event) => setDeviceId(event.target.value)} className="h-9 w-full appearance-none rounded-md border border-zinc-200 bg-white px-3 pr-8 text-sm font-medium outline-none focus:ring-2 focus:ring-emerald-700/20">
                  {devices.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.platform}</option>)}
                </select>
                <ChevronDown className="pointer-events-none absolute right-2.5 top-2.5 size-4 text-zinc-500" />
              </div>
            </div>
            <div className="hidden border-t border-zinc-200 px-4 py-4 lg:block">
              <div className="flex items-center gap-2 text-[11px] text-zinc-500"><Activity className="size-3.5 text-emerald-600" />3 агента на связи</div>
              <div className="mt-2 flex items-center gap-2 text-[11px] text-zinc-500"><RefreshCw className="size-3.5" />Синхронизация 18 сек назад</div>
            </div>
          </aside>

          <main className="min-w-0 bg-white">
            <section className="border-b border-zinc-200 px-4 py-5 sm:px-6">
              <div className="flex flex-col justify-between gap-4 xl:flex-row xl:items-start">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2"><StatusDot status={device.status} /><h1 className="text-xl font-semibold text-zinc-950">{device.name}</h1><Badge variant="outline" className="rounded-md border-zinc-200 text-zinc-600">{device.platform}</Badge></div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-500">
                    <span className="flex items-center gap-1.5"><Server className="size-3.5" />{device.role}</span>
                    <span className="flex items-center gap-1.5"><Globe2 className="size-3.5" />{device.address}</span>
                    <span className="flex items-center gap-1.5"><Clock3 className="size-3.5" />{device.lastSeen}</span>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button variant="outline" className="border-zinc-200"><RefreshCw data-icon="inline-start" />Обновить снимок</Button>
                  <Button className="bg-[#12382e] hover:bg-[#1a4a3d]"><ShieldAlert data-icon="inline-start" />Сформировать план</Button>
                </div>
              </div>
              <div className="mt-5 grid grid-cols-2 divide-x divide-zinc-200 border-y border-zinc-200 sm:grid-cols-4">
                <Metric label="Риск устройства" value={`${device.risk} / 100`} tone="text-red-700" />
                <Metric label="Найдено CVE" value={String(device.cves)} />
                <Metric label="Критические" value={String(device.critical)} tone="text-red-700" />
                <Metric label="Последнее изменение" value="Сегодня, 08:18" />
              </div>
            </section>

            <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as string)} className="gap-0">
              <div className="border-b border-zinc-200 px-4 sm:px-6">
                <TabsList variant="line" className="h-11 gap-5">
                  <TabsTrigger value="cve" className="h-11 px-0"><ShieldAlert />CVE <span className="ml-1 rounded bg-red-50 px-1.5 py-0.5 text-[10px] text-red-700">{device.cves}</span></TabsTrigger>
                  <TabsTrigger value="events" className="h-11 px-0"><Activity />Events <span className="ml-1 rounded bg-zinc-100 px-1.5 py-0.5 text-[10px] text-zinc-600">{events.length}</span></TabsTrigger>
                </TabsList>
              </div>

              <TabsContent value="cve" className="m-0">
                <div className="grid min-h-[600px] grid-cols-1 2xl:grid-cols-[minmax(0,1fr)_340px]">
                  <div className="min-w-0">
                    <div className="flex flex-col gap-3 border-b border-zinc-200 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-6">
                      <div className="relative w-full sm:max-w-xs"><Search className="absolute left-2.5 top-2 size-4 text-zinc-400" /><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE, пакет или описание" className="border-zinc-200 pl-8" /></div>
                      <div className="flex items-center gap-1 overflow-x-auto">
                        <ListFilter className="mr-1 size-4 shrink-0 text-zinc-400" />
                        {(['all', 'critical', 'high', 'medium'] as const).map((item) => (
                          <button key={item} onClick={() => setSeverity(item)} className={cn('h-7 shrink-0 rounded-md px-2.5 text-xs font-medium transition-colors', severity === item ? 'bg-zinc-900 text-white' : 'text-zinc-500 hover:bg-zinc-100')}>{item === 'all' ? 'Все' : severityLabels[item]}</button>
                        ))}
                      </div>
                    </div>
                    <div className="border-b border-zinc-200 bg-zinc-50/70 px-4 py-2 text-[11px] text-zinc-500 sm:px-6">{filteredCves.length} результатов · пересчитано после изменения пакетов в 08:18</div>
                    <div className="divide-y divide-zinc-200">
                      {filteredCves.map((item) => (
                        <button key={item.id} aria-label={`Открыть сведения о ${item.id}`} onClick={() => setSelectedCveId(item.id)} className={cn('grid w-full grid-cols-[1fr_auto] gap-4 px-4 py-4 text-left transition-colors sm:px-6', selectedCve.id === item.id ? 'bg-[#f1f7f3]' : 'hover:bg-zinc-50')}>
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs font-semibold text-zinc-950">{item.id}</span><span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold ring-1 ring-inset', severityStyles[item.severity])}>{severityLabels[item.severity]}</span></div>
                            <p className="mt-2 text-sm font-medium text-zinc-900">{item.title}</p>
                            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-zinc-500"><span className="flex items-center gap-1"><Box className="size-3" />{item.component}</span><span className="flex items-center gap-1"><Network className="size-3" />{item.exposure}</span></div>
                          </div>
                          <div className="text-right"><p className="text-lg font-semibold tabular-nums text-zinc-950">{item.score}</p><p className="text-[10px] text-zinc-500">CVSS</p></div>
                        </button>
                      ))}
                      {filteredCves.length === 0 && <div className="px-6 py-16 text-center"><Search className="mx-auto size-5 text-zinc-400" /><p className="mt-3 text-sm font-medium">Ничего не найдено</p><p className="mt-1 text-xs text-zinc-500">Измените запрос или фильтр опасности.</p></div>}
                    </div>
                  </div>

                  <aside className="border-t border-zinc-200 bg-[#fafbfa] p-5 2xl:border-l 2xl:border-t-0">
                    <div className="flex items-start justify-between gap-3"><div><p className="font-mono text-xs font-semibold text-zinc-500">{selectedCve.id}</p><h2 className="mt-1 text-base font-semibold text-zinc-950">Почему это важно</h2></div><span className={cn('rounded px-2 py-1 text-xs font-semibold ring-1 ring-inset', severityStyles[selectedCve.severity])}>{selectedCve.score}</span></div>
                    <dl className="mt-5 grid grid-cols-2 gap-x-4 gap-y-4 border-y border-zinc-200 py-4 text-xs">
                      <div><dt className="text-zinc-500">Компонент</dt><dd className="mt-1 font-medium text-zinc-900">{selectedCve.component}</dd></div>
                      <div><dt className="text-zinc-500">EPSS</dt><dd className="mt-1 font-medium text-zinc-900">{selectedCve.epss}</dd></div>
                      <div className="col-span-2"><dt className="text-zinc-500">Установлено</dt><dd className="mt-1 break-all font-mono text-[11px] font-medium text-zinc-900">{selectedCve.installed}</dd></div>
                      <div className="col-span-2"><dt className="text-zinc-500">Уровень уверенности</dt><dd className="mt-1 font-medium text-zinc-900">{selectedCve.confidence}</dd></div>
                    </dl>
                    <div className="mt-5"><p className="text-xs font-semibold text-zinc-900">Доказательства применимости</p><ul className="mt-3 space-y-2.5">{selectedCve.evidence.map((evidence) => <li key={evidence} className="flex gap-2 text-xs leading-5 text-zinc-600"><Check className="mt-0.5 size-3.5 shrink-0 text-emerald-700" />{evidence}</li>)}</ul></div>
                    <div className="mt-5 border-l-2 border-emerald-700 bg-emerald-50/60 px-3 py-3"><p className="text-xs font-semibold text-emerald-950">Рекомендуемое действие</p><p className="mt-1.5 text-xs leading-5 text-emerald-900/80">{selectedCve.action}</p></div>
                    <Button onClick={queueProbe} disabled={probeState === 'queued'} variant="outline" className="mt-5 w-full border-zinc-300 bg-white">{probeState === 'queued' ? <RefreshCw className="animate-spin" /> : <Play />}{probeState === 'queued' ? 'Проверка поставлена в очередь' : 'Запустить безопасную проверку'}</Button>
                    <p className="mt-2 text-center text-[10px] leading-4 text-zinc-500">Только разрешённый probe без получения доступа</p>
                  </aside>
                </div>
              </TabsContent>

              <TabsContent value="events" className="m-0">
                <div className="px-4 py-4 sm:px-6">
                  <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center"><div><h2 className="text-sm font-semibold text-zinc-950">Активность устройства</h2><p className="mt-1 text-xs text-zinc-500">Записи сгруппированы по контексту и временному окну.</p></div><Button variant="outline" className="self-start border-zinc-200"><Filter />Фильтры</Button></div>
                  <div className="mt-5 border-t border-zinc-200">
                    {events.map((event) => {
                      const Icon = eventIcons[event.type];
                      return (
                        <article key={event.id} className="grid grid-cols-[48px_minmax(0,1fr)] border-b border-zinc-200 py-4 sm:grid-cols-[72px_40px_minmax(0,1fr)_auto] sm:gap-3">
                          <time className="pt-1 text-xs font-semibold tabular-nums text-zinc-700">{event.time}</time>
                          <span className={cn('grid size-8 place-items-center rounded-md ring-1 ring-inset', eventTone[event.severity])}><Icon className="size-4" /></span>
                          <div className="col-start-2 mt-2 min-w-0 sm:col-start-3 sm:mt-0"><div className="flex flex-wrap items-center gap-2"><h3 className="text-sm font-semibold text-zinc-950">{event.title}</h3><span className="rounded bg-zinc-100 px-1.5 py-0.5 text-[10px] font-medium text-zinc-600">{event.records} записей</span></div><p className="mt-1 text-xs leading-5 text-zinc-600">{event.summary}</p><div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-zinc-500"><span>{event.period}</span><span>{event.actor}</span><span className="font-mono">{event.id}</span></div></div>
                          <Button variant="ghost" size="sm" className="col-start-2 mt-2 justify-self-start text-zinc-600 sm:col-start-4 sm:mt-0">Открыть</Button>
                        </article>
                      );
                    })}
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </main>
        </div>

        <div className="fixed bottom-3 right-3 rounded-md border border-zinc-200 bg-white px-2.5 py-1.5 text-[10px] font-medium text-zinc-500 shadow-sm">Демо-данные · MVP интерфейс</div>
      </div>
    </TooltipProvider>
  );
}
