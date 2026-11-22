'use strict';
const $ = s => document.querySelector(s);
const e = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const num = n => Number(n || 0).toLocaleString();
const u = encodeURIComponent;
function bytes(n) { n = Number(n || 0); const U = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return (i < 2 || n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + U[i]; }
function bps(n) { n = Number(n || 0); if (n >= 1e9) return [(n / 1e9).toFixed(2), 'Gbps']; if (n >= 1e6) return [(n / 1e6).toFixed(n >= 1e7 ? 0 : 1), 'Mbps']; return [(n / 1e3).toFixed(0), 'kbps']; }
const bpsT = n => bps(n).join(' ');
function ago(ts) { const s = Math.max(0, Date.now() / 1000 - ts); if (s < 60) return Math.floor(s) + ' seconds ago'; if (s < 3600) return Math.floor(s / 60) + ' min ago'; if (s < 86400) return Math.floor(s / 3600) + ' h ago'; return Math.floor(s / 86400) + ' days ago'; }
function left(ts) { const s = Math.max(0, ts - Date.now() / 1000); if (s > 5 * 365 * 86400) return 'permanent'; if (s < 3600) return Math.ceil(s / 60) + ' min left'; if (s < 86400 * 2) return Math.floor(s / 3600) + 'h ' + Math.floor(s % 3600 / 60) + 'm left'; return Math.floor(s / 86400) + ' days left'; }
const clock = ts => new Date(ts * 1000).toLocaleTimeString([], {hour12: false});
function when(ts) { const d = new Date(ts * 1000), t = new Date(); return (d.toDateString() === t.toDateString() ? '' : d.toLocaleDateString([], {month: 'short', day: 'numeric'}) + ' ') + clock(ts); }
const RANGES = {'1h': 'Last hour', '24h': '24 hours', '7d': '7 days', '30d': '30 days'};
let range = '24h'; try { range = localStorage.getItem('hc_range') || '24h'; } catch (x) {}
let PROMPT = '', HOMEXY = null, STEP = 0, GEO = null, forceRender = false, WORLD = null, timer = null, loading = false, lastOk = 0;
const NPM_AUTHENTIK = `proxy_buffers 8 16k;
proxy_buffer_size 32k;

location / {
    proxy_pass          $forward_scheme://$server:$port;
    proxy_set_header    Host $host;
    proxy_set_header    X-Forwarded-Proto $scheme;
    proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header    X-Real-IP $remote_addr;
    proxy_http_version  1.1;
    proxy_set_header    Upgrade $http_upgrade;
    proxy_set_header    Connection $http_connection;

    auth_request        /outpost.goauthentik.io/auth/nginx;
    error_page          401 = @goauthentik_proxy_signin;
    auth_request_set    $auth_cookie $upstream_http_set_cookie;
    add_header          Set-Cookie $auth_cookie;

    auth_request_set    $authentik_username $upstream_http_x_authentik_username;
    proxy_set_header    X-authentik-username $authentik_username;
}

location /outpost.goauthentik.io {
    proxy_pass              http://AUTHENTIK-INTERNAL-ADDRESS:9000/outpost.goauthentik.io;
    proxy_set_header        Host $host;
    proxy_set_header        X-Original-URL $scheme://$http_host$request_uri;
    add_header              Set-Cookie $auth_cookie;
    auth_request_set        $auth_cookie $upstream_http_set_cookie;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
}

location @goauthentik_proxy_signin {
    internal;
    add_header Set-Cookie $auth_cookie;
    return 302 https://AUTHENTIK-PUBLIC-NAME/outpost.goauthentik.io/start?rd=$scheme://$http_host$request_uri;
}`;
const UNSHIP = 'systemctl disable --now portal-shipper; rm -f /etc/systemd/system/portal-shipper.service /etc/portal-shipper.json /usr/local/sbin/portal-shipper.py /var/lib/portal-shipper.json; systemctl daemon-reload';
const PAGES = [['home', 'Home'], ['proxy', 'Reverse proxy'], ['perimeter', 'Perimeter'], ['devices', 'Devices'], ['family', 'Family browsing'], ['internet', 'Internet'], ['traffic', 'Traffic'], ['netflow', 'NetFlow'], ['bans', 'Bans'], ['gateway', 'Gateway'], ['connections', 'Connections'], ['settings', 'Settings']];

async function api(name, params) {
  const qs = new URLSearchParams(Object.assign({range}, params || {})).toString();
  const r = await fetch('/api/' + name + '?' + qs, {credentials: 'same-origin'});
  if (r.status === 401) { const j = await r.json().catch(() => ({})); if (j.error === 'setup') showSetup(); else showLogin(); throw new Error('login'); }
  const d = await r.json(); if (!r.ok) throw new Error(d.error || r.status); return d;
}
async function post(path, body) {
  const r = await fetch(path, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-Requested-With': 'homecommand'}, body: JSON.stringify(body || {})});
  const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.error || ('Error ' + r.status)); return d;
}
function route() {
  const h = location.hash.replace(/^#\/?/, '') || 'home'; const [p, qs] = h.split('?'); const parts = p.split('/');
  return {page: parts[0], arg: parts.slice(1).map(decodeURIComponent).join('/'), q: Object.fromEntries(new URLSearchParams(qs || ''))};
}
function href(page, q) { const s = new URLSearchParams(q).toString(); return '#/' + page + (s ? '?' + s : ''); }

// ---------- building blocks ----------
const card = (title, right, body, opt) => `<section class="card" style="${(opt && opt.style) || ''}"><div class="hd"><h2 class="lbl">${title}</h2><span class="muted small">${right || ''}</span></div><div class="bd ${opt && opt.flush ? 'flush' : ''}">${body}</div></section>`;
function tbl(cols, rows, empty) {
  if (!rows || !rows.length) return `<div class="empty">${empty || 'Nothing in this period.'}</div>`;
  const stack = cols.some(c => c.h === '');   // tables with a button column fold into cards on phones so the buttons stay on screen
  return `<div class="tw"><table class="${stack ? 'stack' : ''}"><thead><tr>${cols.map(c => `<th scope="col" class="${c.r ? 'r' : ''}">${c.h}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${cols.map(c => `<td class="${c.r ? 'r ' : ''}${c.c || ''}${c.h === '' ? ' act' : ''}" data-l="${e(c.h)}"${c.t ? ` title="${e(c.t(r))}"` : ''}>${c.f(r)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}
const barc = (n, max, txt) => `<div class="barcell"><i style="width:${Math.max(2, Math.round(100 * n / (max || 1)))}%"></i><span>${txt ?? num(n)}</span></div>`;
const ipl = ip => `<a class="mono" href="#/ip/${e(ip)}">${e(ip)}</a>`;
const devl = (mac, name) => mac ? `<a href="#/device/${e(mac)}">${e(name)}</a>` : e(name);
const stat = (v, l, cls) => `<div><div class="hero ${cls || ''}">${v}</div><div class="muted">${l}</div></div>`;
const banBtn = (ip, banned, sm) => banned ? `<span class="pill ok">Banned</span>` : `<button class="btn ${sm ? 'sm' : ''}" data-act='${e(JSON.stringify({action: 'ban', ip, hours: 24, reason: 'banned from portal'}))}' data-confirm="Ban ${e(ip)} for 24 hours?">Ban 24h</button>`;
function bars(s, color) {
  const v = s.v, max = Math.max(1, ...v), w = 600 / v.length;
  return `<svg viewBox="0 0 600 70" preserveAspectRatio="none" style="width:100%;height:70px" role="img" aria-label="Activity over time, peak ${num(max)} per interval">${v.map((x, i) => `<rect x="${(i * w).toFixed(1)}" y="${(68 - 66 * x / max).toFixed(1)}" width="${Math.max(1, w - 1.5).toFixed(1)}" height="${(66 * x / max + 2).toFixed(1)}" fill="${color || '#7FB8FF'}"><title>${when(s.start + i * s.step)}: ${num(x)}</title></rect>`).join('')}</svg><div class="muted small" style="display:flex;justify-content:space-between"><span>${when(s.start)}</span><span>peak ${num(max)}</span><span>now</span></div>`;
}
function lines(pts, h) {   // pts: [[t, a, b]]
  if (!pts.length) return '<div class="empty">Collecting data…</div>';
  const max = Math.max(1, ...pts.map(p => Math.max(p[1], p[2]))), n = Math.max(1, pts.length - 1);
  const ln = k => pts.map((p, i) => `${(600 * i / n).toFixed(1)},${(h - 3 - (h - 6) * p[k] / max).toFixed(1)}`).join(' ');
  return `<svg viewBox="0 0 600 ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px" role="img" aria-label="Internet use over time, peak ${bpsT(max)}"><polyline points="${ln(2)}" fill="none" stroke="#6B7684" stroke-width="2" vector-effect="non-scaling-stroke"/><polyline points="${ln(1)}" fill="none" stroke="#7FB8FF" stroke-width="2" vector-effect="non-scaling-stroke"/></svg><div class="muted small" style="display:flex;justify-content:space-between"><span>${when(pts[0][0])}</span><span>peak ${bpsT(max)} · blue in, grey out</span><span>now</span></div>`;
}
function worldMap(countries, target) {
  if (!WORLD) return '<div class="empty">Loading map…</div>';
  const by = Object.fromEntries(countries.map(c => [c.cc, c])), max = Math.max(1, ...countries.map(c => c.n));
  const link = cc => target(cc);
  let shapes = '', dots = '';
  for (const cc in WORLD) {
    const c = by[cc], w = WORLD[cc];
    const p = `<path d="${w.d}"${c ? ` style="fill:${c.loose ? '#5A2B2B' : '#2E3A47'}"` : ''}><title>${e(w.n)}${c ? ': ' + num(c.n) + ' attempts from ' + num(c.ips) + ' addresses' : ''}</title></path>`;
    shapes += c ? `<a href="${link(cc)}">${p}</a>` : p;
    if (c) dots += `<a href="${link(cc)}"><circle cx="${w.c[0]}" cy="${w.c[1]}" r="${(3 + 13 * Math.sqrt(c.n / max)).toFixed(1)}" fill="${c.loose ? '#FF8A80' : '#8A95A3'}" fill-opacity=".45" stroke="${c.loose ? '#FF8A80' : '#C9D1DB'}" stroke-width="1"><title>${e(w.n)}: ${num(c.n)} attempts</title></circle></a>`;
  }
  return `<svg class="map" viewBox="0 28 720 300" style="width:100%;height:auto" role="img" aria-label="World map of attack sources">${shapes}${dots}${HOMEXY ? `<circle cx="${HOMEXY[0]}" cy="${HOMEXY[1]}" r="3.5" fill="#7FB8FF"/><text x="${HOMEXY[0] + 6}" y="${HOMEXY[1] - 3}" fill="#C9D1DB" font-size="10">Home</text>` : ''}</svg>`;
}
function countryList(countries, target, n) {
  return countries.slice(0, n || 6).map(c => `<div class="kv"><span><a href="${target(c.cc)}" class="${c.loose ? 'red b' : ''}" style="${c.loose ? '' : 'color:var(--text)'}">${e(c.name)}</a></span><span class="${c.loose ? 'red b' : 'muted'}">${num(c.n)}${c.loose ? ' · ' + c.loose + ' unbanned' : ''}</span></div>`).join('') || '<div class="empty">No attempts recorded.</div>';
}
function filters(page, q, labels) {
  const on = Object.keys(q).filter(k => labels[k]);
  if (!on.length) return '';
  return `<div class="chips"><span class="muted">Showing only:</span>${on.map(k => { const r = Object.assign({}, q); delete r[k]; return `<a class="chip on" href="${href(page, r)}" title="Remove this filter">${labels[k]}: ${e(q[k])} ✕</a>`; }).join('')}<a class="chip" href="#/${page}">Clear all</a></div>`;
}
const DUR = [[4, '4 hours'], [24, '24 hours'], [168, '7 days'], [720, '30 days'], [8760, '1 year'], [0, 'Permanently']];
const banBox = (ip, reason) => `<span class="banbox"><select class="btn" data-banfor aria-label="Ban duration">${DUR.map(([h, l]) => `<option value="${h}"${h === 24 ? ' selected' : ''}>${l}</option>`).join('')}</select><button class="btn pri" data-ban="${e(ip)}" data-reason="${e(reason || 'banned from portal')}">Ban</button></span>`;
const unbanBtn = ip => `<button class="btn" data-act='${e(JSON.stringify({action: 'unban', ip}))}' data-confirm="Remove the ban on ${e(ip)}? It will be able to reach your reverse proxy again.">Unban</button>`;
const factList = list => `<dl class="facts">${list.map(f => `<div><dt>${e(f[0])}</dt><dd>${f[2] ? `<a href="${e(f[2])}">${e(f[1])}</a>` : e(f[1])}</dd></div>`).join('')}</dl>`;
const tonePill = it => it.outcome ? `<span class="pill ${it.tone === 'bad' ? 'attack' : it.tone === 'ok' ? 'ok' : 'anomaly'}">${e(it.outcome)}</span>` : '';
function itemActs(it) {
  let acts = '';
  if (it.status === 'open') {
    if (it.stype === 'ip' && !it.banned) acts += banBox(it.subject, it.label);
    if (it.stype === 'device') acts += `<button class="btn pri" data-act='${e(JSON.stringify({action: 'block-device', mac: it.subject}))}' data-confirm="Block this device from the network? It will lose all connectivity until you unblock it.">Block device</button>`;
    if (it.kind === 'device') acts += `<button class="btn ghost" data-name="${e(it.subject)}">It's mine, name it</button>`;
  }
  if (it.status === 'open' && it.kind === 'dest') acts += `<button class="btn" data-act='${e(JSON.stringify({action: 'known', id: it.id}))}'>Mark as known</button>`;
  else if (it.status === 'open' || it.status === 'handled') acts += `<button class="btn" data-act='${e(JSON.stringify({action: 'dismiss', id: it.id}))}' title="Remove this alert from your lists. The records stay searchable.">Dismiss</button>`;
  if (it.stype === 'ip' && it.banned) acts += unbanBtn(it.subject);
  return acts;
}
const itemMeta = it => { const m = ['last seen ' + ago(it.last)]; if (it.hits > 1) m.push('seen ' + num(it.hits) + ' times'); if (it.more) m.push(`+${it.more} more alert${it.more === 1 ? '' : 's'} about the same ${it.stype === 'ip' ? 'address' : 'device'}`); return m.join(' · '); };
function itemRow(it) {
  return `<article class="item"><div class="txt"><div class="chips"><span class="pill info">${e(it.label)}</span>${tonePill(it)}<span class="muted small">${itemMeta(it)}</span></div><div class="b" style="font-size:15.5px">${e(it.headline)}</div>${factList(it.facts)}</div><div class="acts"><a class="btn" href="#/item/${it.id}">Investigate</a>${itemActs(it)}</div></article>`;
}

// ---------- pages ----------
const V = {};
V.home = async () => {
  const d = await api('home'); const n = d.items.length, I = d.internet, st = I.speedtest || {}; HOMEXY = d.home_xy;
  if (!d.setup_done) return `<section style="display:flex;flex-direction:column;gap:10px"><h1 class="verdict">Welcome to Home Command</h1><p class="muted" style="margin:0;font-size:15px">Nothing is connected yet. The walkthrough takes about ten minutes and connects your gateway, reverse proxy and DNS filter.</p><div><a class="btn pri" href="#/setup">Start the setup walkthrough</a></div></section>`;
  const rx = bps(I.rx), tx = bps(I.tx);
  const handledTxt = `${num(d.proxy.probes)} web probes turned away, ${num(d.perimeter.drops)} inbound connections dropped at the gateway, ${num(d.bans.mine)} of your own bans in force.`;
  return `
<section style="display:flex;flex-direction:column;gap:6px"><h1 class="verdict ${n ? 'amber' : ''}">${n ? n + (n === 1 ? ' thing needs' : ' things need') + ' your attention' : 'All clear'}</h1>
<p class="muted" style="margin:0;font-size:15px">${n ? 'Everything else was handled without you: ' : 'Handled without you: '}${handledTxt}</p></section>
${n ? `<section class="card" style="flex:none"><div class="hd"><h2 class="lbl">Needs attention</h2><span class="muted small">One row per address or device</span></div><div class="bd flush">${d.items.map(itemRow).join('')}</div></section>` : ''}
<div class="row">
${card('Internet', 'In use right now', `<div style="display:flex;gap:28px;flex-wrap:wrap">${stat(`${rx[0]} <small>${rx[1]}</small>`, 'coming in')}${stat(`${tx[0]} <small>${tx[1]}</small>`, 'going out')}</div>
${lines(I.hour, 70)}
<div><div class="kv"><span class="muted">Line speed${st.at ? ' (tested ' + when(st.at) + ')' : ''}</span><span>${st.down ? bpsT(st.down * 1e6) + ' down · ' + bpsT(st.up * 1e6) + ' up' : 'not tested yet'}</span></div>
<div class="kv"><span class="muted">Used today</span><span>${bytes(I.today[0])} down · ${bytes(I.today[1])} up</span></div>
<div class="kv"><span class="muted">Biggest user now</span><span>${I.top ? devl(I.top.mac, I.top.label || I.top.name) + ' · ' + bpsT(I.top.rate * 8) : 'nobody in particular'}</span></div></div>
<div style="margin-top:auto;text-align:right"><a href="#/internet">Usage by device and by day</a></div>`, {style: 'flex:1 1 340px'})}
${card('Where attacks come from', 'Click a country to see what it tried', `<div class="row" style="gap:0"><div style="flex:999 1 400px;min-width:0;padding:10px 6px 6px 12px">${worldMap(d.countries, cc => href('proxy', {cc}))}</div>
<div style="flex:1 1 220px;padding:12px 18px;min-width:0">${countryList(d.countries, cc => href('proxy', {cc}))}<div class="kv"><span><a href="#/proxy">All ${d.countries.length} countries</a></span><span class="muted">${num(d.proxy.probes + d.perimeter.drops)}</span></div><div class="muted small" style="margin-top:10px">Grey: turned away or banned. Red: active and not banned.</div></div></div>`, {flush: true, style: 'flex:999 1 560px'})}
</div>
<div class="row">
${card('Reverse proxy', d.proxy.loose ? `<span class="red b">${d.proxy.loose} unbanned</span>` : 'All handled', `<a href="#/proxy" style="color:inherit">${stat(num(d.proxy.sources), 'outside addresses probed your domains')}</a>
<div><div class="muted small">What they went after</div>${d.proxy.paths.map(p => `<div class="kv"><span title="${e(p.why)}"><a class="mono" style="color:var(--text)" href="${href('proxy', {q: p.path})}">${e(p.path.slice(0, 34) || '/')}</a></span><span class="muted">${num(p.n)}</span></div>`).join('') || '<div class="empty">Nothing yet.</div>'}</div>
<div class="kv" style="margin-top:auto"><span class="muted">${num(d.proxy.requests)} requests in total</span><a href="#/proxy">Open</a></div>`)}
${card('Perimeter', d.perimeter.threats ? `<span class="red b">${d.perimeter.threats} threats</span>` : 'All handled', `<a href="#/perimeter" style="color:inherit">${stat(num(d.perimeter.drops), 'inbound connections dropped at the gateway')}</a>
<div><div class="muted small">What they knocked on</div>${d.perimeter.ports.map(p => `<div class="kv"><span><a style="color:var(--text)" href="${href('perimeter', {port: p.dpt})}">${e(p.name)}</a></span><span class="muted">${num(p.n)}</span></div>`).join('') || '<div class="empty">Nothing yet.</div>'}</div>
<div class="kv" style="margin-top:auto"><span class="muted">${num(d.perimeter.threats)} threat detections</span><a href="#/perimeter">Open</a></div>`)}
${card('Devices', d.devices.anomalies ? `<span class="amber b">${d.devices.anomalies} anomalies</span>` : 'Nothing unusual', `<a href="#/devices" style="color:inherit">${stat(num(d.devices.iot), 'IoT devices talking to the internet')}</a>
<div><div class="muted small">Busiest, and who they talk to most</div>${d.devices.top.map(t => `<div class="kv"><span>${devl(t.mac, t.name)} → ${e(t.top)}</span><span class="muted nowrap">${bytes(t.b)}</span></div>`).join('') || '<div class="empty">Nothing yet.</div>'}</div>
<div class="kv" style="margin-top:auto"><span class="muted">${num(d.devices.online)} devices online${d.devices.new ? ' · ' + d.devices.new + ' new' : ''}</span><a href="#/devices">Open</a></div>`)}
${card('Family browsing', 'From AdGuard', `<a href="#/family" style="color:inherit">${stat(num(d.family.lookups), `site lookups, ${d.family.lookups ? Math.round(100 * d.family.blocked / d.family.lookups) : 0}% blocked as ads or trackers`)}</a>
<div><div class="muted small">Most looked up</div>${d.family.domains.map(t => `<div class="kv"><span><a style="color:var(--text)" href="${href('family', {domain: t.domain})}">${e(t.domain)}</a></span><span class="muted nowrap">${t.c} device${t.c === 1 ? '' : 's'}</span></div>`).join('') || '<div class="empty">Nothing yet.</div>'}</div>
<div class="kv" style="margin-top:auto"><span class="muted">${num(d.family.clients)} devices using it</span><a href="#/family">Open</a></div>`)}
</div>
<div class="row">
${card('Live activity', 'Every source, newest first', tbl([{h: 'Time', f: r => `<span class="muted nowrap">${clock(r[0])}</span>`}, {h: 'Where', f: r => e(r[1])}, {h: 'What happened', f: r => `<a style="color:var(--text)" href="${e(r[4])}">${e(r[2])}</a>`}, {h: 'Outcome', f: r => `<span class="${r[3] === 'Needs you' ? 'red b' : r[3] === 'Got a response' ? 'amber' : 'muted'} nowrap">${e(r[3])}</span>`}], d.feed), {flush: true, style: 'flex:999 1 560px'})}
${card('Bans in force', '', `<div style="display:flex;gap:24px">${stat(num(d.bans.mine), 'earned here')}${stat(`<span class="muted">${num(d.bans.community)}</span>`, 'from the community list')}</div>
<div>${d.bans.list.map(b => `<div class="kv"><span>${ipl(b.ip)} · ${e(b.why)}</span><span class="muted nowrap">${left(b.until)}</span></div>`).join('')}</div>
<div style="margin-top:auto"><a class="btn" href="#/bans">Ban an address or see all bans</a></div>`, {style: 'flex:1 1 320px'})}
</div>
${d.handled.length ? card('Handled automatically', 'No action needed', d.handled.map(itemRow).join(''), {flush: true, style: 'flex:none'}) : ''}`;
};
V.proxy = async r => {
  const d = await api('proxy', r.q); const q = r.q, mx = a => Math.max(1, ...a.map(x => x.n)), add = o => href('proxy', Object.assign({}, q, o));
  const all = q.all === '1';
  return `<div class="row" style="align-items:center;justify-content:space-between"><h1 class="verdict" style="font-size:26px">Reverse proxy: who is touching your domains</h1>
<div class="chips"><a class="chip ${all ? '' : 'on'}" href="${href('proxy', Object.fromEntries(Object.entries(q).filter(([k]) => k !== 'all')))}">Failed attempts only</a><a class="chip ${all ? 'on' : ''}" href="${add({all: 1})}">All outside requests</a></div></div>
${filters('proxy', q, {ip: 'Address', host: 'Domain', cc: 'Country', q: 'Contains', status: 'Result code'})}
<div class="card" style="flex:none"><div class="bd"><div class="stats">${stat(num(d.total.n), all ? 'requests from outside' : 'failed attempts')}${stat(num(d.total.ips), 'different addresses')}${stat(num(d.total.ok || 0), 'got a response', d.total.ok && !all ? 'amber' : '')}</div>${bars(d.series)}</div></div>
<div class="row">
${card('Sources', 'Click an address to investigate', tbl([{h: 'Address', f: x => ipl(x.ip)}, {h: 'From', f: x => `<a style="color:var(--text)" href="${add({cc: x.cc})}">${e(x.country)}</a><div class="muted small">${e(x.owner)}</div>`}, {h: 'Attempts', f: x => barc(x.n, mx(d.sources))}, {h: '', f: x => banBtn(x.ip, x.banned, 1)}], d.sources), {flush: true, style: 'flex:1 1 480px'})}
${card('What they went after', 'Click to see who asked', tbl([{h: 'Page', c: 'clip', t: x => x.path, f: x => `<a class="mono" style="color:var(--text)" href="${add({q: x.path})}">${e(x.path || '/')}</a><div class="muted small">${e(x.why)}</div>`}, {h: 'Attempts', f: x => barc(x.n, mx(d.paths))}, {h: 'From', r: 1, f: x => num(x.ips)}, {h: 'Answered', r: 1, f: x => x.ok ? `<span class="amber b">${num(x.ok)}</span>` : '0'}], d.paths), {flush: true, style: 'flex:1 1 480px'})}
</div>
<div class="row">
${card('Your domains', 'All traffic in this period', tbl([{h: 'Domain', f: x => `<a style="color:var(--text)" href="${href('proxy', {all: 1, host: x.host})}">${e(x.host)}</a>`}, {h: 'Requests', f: x => barc(x.n, mx(d.all_hosts))}, {h: 'Visitors', r: 1, f: x => num(x.ips)}, {h: 'Failed from outside', r: 1, f: x => x.bad ? `<a href="${href('proxy', {host: x.host})}">${num(x.bad)}</a>` : '0'}], d.all_hosts), {flush: true, style: 'flex:1 1 420px'})}
${card('Tools they used', '', tbl([{h: 'Client', c: 'clip', t: x => x.ua, f: x => `<a style="color:var(--text)" href="${add({q: x.ua})}">${e(x.ua || '(none)')}</a>`}, {h: 'Attempts', f: x => barc(x.n, mx(d.tools))}], d.tools), {flush: true, style: 'flex:1 1 320px'})}
${card('Results and countries', '', `<div>${d.status.map(s => `<div class="kv"><span><a style="color:var(--text)" href="${add({status: s.status})}">${e(s.outcome)} (${s.status})</a></span><span class="muted">${num(s.n)}</span></div>`).join('')}</div><div class="lbl">Countries</div><div>${countryList(d.countries, cc => add({cc}), 8)}</div>`, {style: 'flex:1 1 260px'})}
</div>
${card('Every matching request', 'Newest first, up to 200', tbl([{h: 'Time', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'Address', f: x => ipl(x.ip) + `<div class="muted small">${e(x.cc)} · ${e(x.owner)}</div>`}, {h: 'Domain', f: x => e(x.host)}, {h: 'Request', c: 'clip', t: x => x.uri, f: x => `<span class="mono">${e(x.method)} ${e(x.uri)}</span><div class="muted small">${e(x.why)}</div>`}, {h: 'Result', f: x => `<span class="${x.status < 400 ? 'amber b' : 'muted'} nowrap">${e(x.outcome)} (${x.status})</span>`}, {h: 'Client', c: 'clip', t: x => x.ua, f: x => `<span class="muted">${e(x.ua)}</span>`}], d.rows), {flush: true, style: 'flex:none'})}`;
};
V.perimeter = async r => {
  const d = await api('perimeter', r.q), q = r.q, mx = a => Math.max(1, ...a.map(x => x.n)), add = o => href('perimeter', Object.assign({}, q, o));
  return `<h1 class="verdict" style="font-size:26px">Perimeter: what the gateway turned away</h1>
${filters('perimeter', q, {ip: 'Address', cc: 'Country', port: 'Port'})}
<div class="card" style="flex:none"><div class="bd"><div class="stats">${stat(num(d.total.n), 'inbound connections dropped')}${stat(num(d.total.ips), 'different addresses')}${stat(num(d.threats.length), 'threat detections', d.threats.length ? 'red' : '')}</div>${bars(d.series, '#8A95A3')}</div></div>
${d.threats.length ? card('Threat detections from UniFi', '', d.threats.map(itemRow).join(''), {flush: true, style: 'flex:none'}) : ''}
<div class="row">
${card('Who knocked', 'Click an address to investigate', tbl([{h: 'Address', f: x => ipl(x.ip)}, {h: 'From', f: x => `<a style="color:var(--text)" href="${add({cc: x.cc})}">${e(x.country)}</a><div class="muted small">${e(x.owner)}</div>`}, {h: 'Knocks', f: x => barc(x.n, mx(d.sources))}, {h: 'Ports tried', r: 1, f: x => x.ports > 5 ? `<span class="amber b">${x.ports}</span>` : x.ports}, {h: '', f: x => banBtn(x.ip, x.banned, 1)}], d.sources), {flush: true, style: 'flex:1 1 480px'})}
${card('What they knocked on', '', tbl([{h: 'Service', f: x => `<a style="color:var(--text)" href="${add({port: x.dpt})}">${e(x.name)}</a>`}, {h: 'Knocks', f: x => barc(x.n, mx(d.ports))}, {h: 'From', r: 1, f: x => num(x.ips)}], d.ports), {flush: true, style: 'flex:1 1 340px'})}
${card('Countries', '', `<div>${countryList(d.countries, cc => add({cc}), 12)}</div>`, {style: 'flex:1 1 240px'})}
</div>
${card('Connections that were let in', 'Outside addresses that reached something you opened', tbl([{h: 'Address', f: x => ipl(x.ip) + `<div class="muted small">${e(x.cc)} · ${e(x.owner)}</div>`}, {h: 'Reached', f: x => `${e(x.dst_ip)} port ${x.dst_port}`}, {h: 'Connections', r: 1, f: x => num(x.n)}, {h: 'Data', r: 1, f: x => bytes(x.b)}], d.inbound, 'No inbound connections recorded.'), {flush: true, style: 'flex:none'})}
${card('Every dropped connection', 'Newest first, up to 200', tbl([{h: 'Time', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'Address', f: x => ipl(x.src) + `<div class="muted small">${e(x.country)} · ${e(x.owner)}</div>`}, {h: 'Tried to reach', f: x => e(x.port) + ` <span class="muted">${e(x.proto)}</span>`}, {h: 'Rule', f: x => `<span class="muted">${e(x.rule)}</span>`}], d.rows), {flush: true, style: 'flex:none'})}`;
};
V.devices = async r => {
  const d = await api('devices'), net = r.q.net ?? (d.iot[0] || ''), show = d.devices.filter(x => !net || x.network === net);
  show.sort((a, b) => ((b.use && b.use.b) || 0) - ((a.use && a.use.b) || 0));
  const mxb = Math.max(1, ...show.map(x => (x.use && x.use.b) || 0));
  return `<h1 class="verdict" style="font-size:26px">Devices: what each one is talking to</h1>
<div class="chips"><a class="chip ${net ? '' : 'on'}" href="#/devices?net=">All networks</a>${d.networks.map(n => `<a class="chip ${n === net ? 'on' : ''}" href="${href('devices', {net: n})}">${e(n)}</a>`).join('')}</div>
${card(net || 'All networks', `${show.length} devices · click one to see every destination`, tbl([
  {h: 'Device', f: x => devl(x.mac, x.label || x.name) + (x.flags.length ? ` <span class="pill anomaly">${x.flags.includes('device') ? 'New' : 'New destination'}</span>` : '') + (x.blocked ? ' <span class="pill attack">Blocked</span>' : '') + `<div class="muted small">${e(x.oui)}</div>`},
  {h: 'Address', f: x => `<span class="mono">${e(x.ip)}</span><div class="muted small">${e(x.network)}</div>`},
  {h: 'Status', f: x => x.online ? (x.rate ? bpsT(x.rate * 8) + ' now' : 'Online') : `<span class="muted">Last seen ${ago(x.last_seen)}</span>`},
  {h: 'Data with the internet', f: x => x.use ? barc(x.use.b, mxb, bytes(x.use.b)) : '<span class="muted">none</span>'},
  {h: 'Sent', r: 1, f: x => x.use ? bytes(x.use.up) : ''}, {h: 'Received', r: 1, f: x => x.use ? bytes(x.use.down) : ''},
  {h: 'Destinations', r: 1, f: x => x.use ? num(x.use.dests) : ''}, {h: 'Blocked', r: 1, f: x => x.use && x.use.blocked ? `<span class="amber b">${num(x.use.blocked)}</span>` : ''}], show), {flush: true, style: 'flex:none'})}`;
};
V.device = async r => {
  const d = await api('device', {mac: r.arg}); if (d.error) return `<div class="empty">${e(d.error)}</div>`;
  const x = d.device, name = x.label || x.name, mxb = Math.max(1, ...d.dests.map(t => t.b));
  return `<div class="row" style="align-items:flex-end;justify-content:space-between"><div><div class="muted"><a href="#/devices">Devices</a> / ${e(x.network)}</div><h1 class="verdict" style="font-size:28px">${e(name)} ${x.blocked ? '<span class="pill attack">Blocked</span>' : ''}</h1>
<div class="muted">${e(x.oui || 'Unknown maker')} · <span class="mono">${e(x.ip)}</span> · <span class="mono">${e(x.mac)}</span> · ${x.wired ? 'wired' : 'Wi-Fi'} via ${e(x.uplink)} · ${x.online ? 'online' : 'last seen ' + ago(x.last_seen)} · first seen ${when(x.first_seen)}</div></div>
<div class="chips">${x.blocked ? `<button class="btn" data-act='${e(JSON.stringify({action: 'unblock-device', mac: x.mac}))}' data-confirm="Unblock ${e(name)}?">Unblock device</button>` : `<button class="btn danger" data-act='${e(JSON.stringify({action: 'block-device', mac: x.mac}))}' data-confirm="Block ${e(name)} from the network? It will lose all connectivity until you unblock it.">Block device</button>`}<button class="btn" data-name="${e(x.mac)}">Rename</button></div></div>
${d.items.filter(i => i.status === 'open').map(itemRow).join('') ? `<section class="card" style="flex:none"><div class="bd flush">${d.items.filter(i => i.status === 'open').map(itemRow).join('')}</div></section>` : ''}
<div class="card" style="flex:none"><div class="bd"><div class="stats">${stat(bytes(d.totals.up), 'sent to the internet')}${stat(bytes(d.totals.down), 'received')}${stat(num(d.dests.length), 'different destinations')}${stat(num(d.totals.n), 'connections')}</div>${bars(d.series)}</div></div>
${card('Who it talks to on the internet', 'Grouped by the company that owns the destination', tbl([
  {h: 'Destination owner', f: t => `<span class="b">${e(t.who)}</span>${t.first && t.first > Date.now() / 1000 - 86400 ? ' <span class="pill anomaly">First seen ' + ago(t.first) + '</span>' : ''}<div class="muted small">${e(t.country)}${t.ips > 1 ? ' · ' + t.ips + ' addresses' : ''}</div>`},
  {h: 'Names it asked for', c: 'clip', t: t => t.domains.join(', '), f: t => t.domains.filter(Boolean).map(e).join('<br>') || '<span class="muted">no name seen (address only)</span>'},
  {h: 'Service', f: t => e(t.services || '') + `<div class="muted small">port ${e(t.ports)}</div>`},
  {h: 'Data', f: t => barc(t.b, mxb, bytes(t.b))}, {h: 'Sent', r: 1, f: t => bytes(t.up)}, {h: 'Received', r: 1, f: t => bytes(t.down)},
  {h: 'Connections', r: 1, f: t => num(t.n)}, {h: 'Last', f: t => `<span class="muted nowrap">${ago(t.last)}</span>`}], d.dests, 'No internet connections recorded in this period.'), {flush: true, style: 'flex:none'})}
<div class="row">
${card('Inside your network', 'Other devices it talked to or tried to reach', tbl([{h: 'Device', f: t => e(t.who) + `<div class="muted small">${e(t.dst_net)}</div>`}, {h: 'Ports', f: t => `<span class="mono">${e(t.ports)}</span>`}, {h: 'Connections', r: 1, f: t => num(t.n)}, {h: 'Blocked', r: 1, f: t => t.blocked ? `<span class="amber b">${num(t.blocked)}</span>` : '0'}], d.internal, 'Nothing internal.'), {flush: true})}
${card('Blocked by firewall rules', '', tbl([{h: 'Tried to reach', f: t => e(t.who)}, {h: 'Service', f: t => e(t.port)}, {h: 'Times', r: 1, f: t => num(t.n)}, {h: 'Rule', f: t => `<span class="muted">${e(t.rule)}</span>`}], d.fw, 'No blocks.'), {flush: true})}
${card('Sites it looked up', 'Only if it uses AdGuard for DNS', tbl([{h: 'Name', f: t => `<a style="color:var(--text)" href="${href('family', {domain: t.domain})}">${e(t.domain)}</a>`}, {h: 'Lookups', r: 1, f: t => num(t.n)}, {h: '', f: t => t.blocked ? '<span class="pill ok">Blocked</span>' : ''}], d.dns, 'This device does not use AdGuard, so its lookups are not visible.'), {flush: true})}
</div>
${card('Every connection', 'Newest first, up to 200', tbl([{h: 'Time', f: t => `<span class="muted nowrap">${when(t.ts)}</span>`}, {h: 'To', f: t => e(t.domain || t.dst_name || t.dst_ip) + `<div class="muted small">${t.dir === 'outgoing' ? e(t.owner) + ' · ' + e(t.cc) : e(t.dst_net)}</div>`}, {h: 'Address', f: t => t.dir === 'outgoing' ? ipl(t.dst_ip) : `<span class="mono">${e(t.dst_ip)}</span>`}, {h: 'Service', f: t => e(t.service || t.port) + ` <span class="muted">${e(t.proto)} ${t.dst_port}</span>`}, {h: 'Data', r: 1, f: t => bytes(t.bytes)}, {h: 'Outcome', f: t => t.action === 'blocked' ? '<span class="amber b">Blocked</span>' : '<span class="muted">Allowed</span>'}], d.rows), {flush: true, style: 'flex:none'})}`;
};
V.family = async r => {
  const d = await api('family', r.q), q = r.q, add = o => href('family', Object.assign({}, q, o)), mx = a => Math.max(1, ...a.map(x => x.n));
  return `<h1 class="verdict" style="font-size:26px">Family browsing${d.name ? ': ' + e(d.name) : ''}</h1>
${filters('family', q, {client: 'Device', domain: 'Site', q: 'Contains', blocked: 'Blocked only'})}
<div class="card" style="flex:none"><div class="bd"><div class="stats">${stat(num(d.total.n), 'site lookups')}${stat(num(d.total.b || 0), 'blocked')}${stat(num(d.total.c), 'devices')}${stat(num(d.total.d), 'different names')}</div>${bars(d.series)}</div></div>
<div class="note">Only devices that use AdGuard for DNS appear here. A lookup shows which site a device contacted, not the pages or content.</div>
<div class="row">
${card('Who', 'Click a device to see only its lookups', tbl([{h: 'Device', f: x => `<a style="color:var(--text)" href="${add({client: x.client})}">${e(x.name)}</a><div class="muted small">${e(x.network || '')} ${x.name === x.client ? '' : e(x.client)}</div>`}, {h: 'Lookups', f: x => barc(x.n, mx(d.clients))}, {h: 'Blocked', r: 1, f: x => num(x.b)}, {h: 'Sites', r: 1, f: x => num(x.d)}], d.clients), {flush: true, style: 'flex:1 1 380px'})}
${card('Sites visited', 'Click to see who', tbl([{h: 'Name', c: 'clip', f: x => `<a style="color:var(--text)" href="${add({domain: x.domain})}">${e(x.domain)}</a>`}, {h: 'Lookups', f: x => barc(x.n, mx(d.domains))}, {h: 'Devices', r: 1, f: x => num(x.c)}], d.domains), {flush: true, style: 'flex:1 1 380px'})}
${card('Blocked', 'Ads, trackers and filtered sites', tbl([{h: 'Name', c: 'clip', f: x => `<a style="color:var(--text)" href="${add({domain: x.domain})}">${e(x.domain)}</a>`}, {h: 'Times', f: x => barc(x.n, mx(d.blocked))}, {h: 'Devices', r: 1, f: x => num(x.c)}], d.blocked), {flush: true, style: 'flex:1 1 380px'})}
</div>
${card('Every lookup', 'Newest first, up to 300', tbl([{h: 'Time', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'Device', f: x => `<a style="color:var(--text)" href="${add({client: x.client})}">${e(x.name)}</a>`}, {h: 'Looked up', f: x => `<a style="color:var(--text)" href="${add({domain: x.domain})}">${e(x.domain)}</a>`}, {h: 'Outcome', f: x => x.blocked ? '<span class="pill ok">Blocked</span>' : '<span class="muted">Allowed</span>'}], d.rows), {flush: true, style: 'flex:none'})}`;
};
V.internet = async () => {
  const d = await api('internet'), I = d.now, st = I.speedtest || {}, rx = bps(I.rx), tx = bps(I.tx), mxd = Math.max(1, ...d.days.map(x => x[1][0] + x[1][1])), mxb = Math.max(1, ...d.devices.map(x => x.b));
  return `<h1 class="verdict" style="font-size:26px">Internet: speed and usage</h1>
<div class="card" style="flex:none"><div class="bd"><div class="stats">${stat(`${rx[0]} <small>${rx[1]}</small>`, 'coming in now')}${stat(`${tx[0]} <small>${tx[1]}</small>`, 'going out now')}${stat(st.down ? bpsT(st.down * 1e6) : '—', 'line speed down' + (st.at ? ', tested ' + when(st.at) : ''))}${stat(st.up ? bpsT(st.up * 1e6) : '—', 'line speed up')}${stat((st.latency ?? '—') + ' <small>ms</small>', 'response time')}${stat(bytes(I.today[0] + I.today[1]), 'used today')}</div>
${lines(d.series.map(s => [s[0], s[1], s[2]]), 120)}<div class="muted small">${e((I.info || {}).isp || '')} · public address <span class="mono">${e((I.info || {}).ip || '')}</span></div></div></div>
<div class="row">
${card('Using the most right now', '', tbl([{h: 'Device', f: x => devl(x.mac, x.label || x.name) + `<div class="muted small">${e(x.network)}</div>`}, {h: 'Speed', r: 1, f: x => bpsT(x.rate * 8)}], d.live, 'Nothing significant right now.'), {flush: true})}
${card('By device', 'Data exchanged with the internet in this period', tbl([{h: 'Device', f: x => devl(x.mac, x.name) + `<div class="muted small">${e(x.net)}</div>`}, {h: 'Total', f: x => barc(x.b, mxb, bytes(x.b))}, {h: 'Down', r: 1, f: x => bytes(x.down)}, {h: 'Up', r: 1, f: x => bytes(x.up)}], d.devices), {flush: true, style: 'flex:2 1 420px'})}
${card('Where the data went', 'By destination owner', tbl([{h: 'Owner', f: x => e(x.who)}, {h: 'Data', r: 1, f: x => bytes(x.b)}, {h: 'Devices', r: 1, f: x => num(x.devs)}], d.dests), {flush: true})}
</div>
${card('By day', 'Last 31 days', tbl([{h: 'Day', f: x => e(x[0])}, {h: 'Total', f: x => barc(x[1][0] + x[1][1], mxd, bytes(x[1][0] + x[1][1]))}, {h: 'Down', r: 1, f: x => bytes(x[1][0])}, {h: 'Up', r: 1, f: x => bytes(x[1][1])}], d.days.slice().reverse()), {flush: true, style: 'flex:none'})}`;
};
V.bans = async () => {
  const d = await api('bans'); const comm = Object.entries(d.counts).filter(([k]) => k === 'CAPI' || k === 'lists').flatMap(([k, v]) => Object.entries(v)).sort((a, b) => b[1] - a[1]);
  return `<h1 class="verdict" style="font-size:26px">Bans</h1>
${card('Ban an address', 'Blocked at the reverse proxy within seconds', `<form id="banform" class="chips"><input type="text" name="ip" placeholder="Address, e.g. 203.0.113.50" aria-label="Address" required style="flex:1 1 220px"><select name="hours" aria-label="Duration" class="btn"><option value="4">4 hours</option><option value="24" selected>24 hours</option><option value="168">7 days</option><option value="720">30 days</option><option value="8760">1 year</option><option value="0">Permanently</option></select><input type="text" name="reason" placeholder="Reason (optional)" aria-label="Reason" style="flex:1 1 220px"><button class="btn pri">Ban</button></form>`, {style: 'flex:none'})}
<div class="row">
${card('In force: yours', `${d.bans.length} addresses`, tbl([{h: 'Address', f: x => ipl(x.ip) + `<div class="muted small">${e(x.country)} · ${e(x.owner)}</div>`}, {h: 'Why', f: x => e(x.why) + `<div class="muted small">${x.origin === 'cscli' ? 'by hand' : 'automatic'} · ${e(x.scenario)}</div>`}, {h: 'Remaining', f: x => `<span class="nowrap">${left(x.until)}</span>`}, {h: 'Gateway', f: x => x.gw ? '<span class="pill ok">Also at gateway</span>' : `<button class="btn sm" data-act='${e(JSON.stringify({action: 'gw-ban', ip: x.ip}))}' title="Also drop this address at the gateway, on every port">Send to gateway</button>`}, {h: '', f: x => `<button class="btn sm" data-act='${e(JSON.stringify({action: 'unban', ip: x.ip}))}' data-confirm="Remove the ban on ${e(x.ip)}?">Unban</button>`}], d.bans, 'No bans of your own in force.'), {flush: true, style: 'flex:2 1 520px'})}
${card('In force: community list', `${num(comm.reduce((a, c) => a + c[1], 0))} addresses`, `<div class="muted small">Known-bad addresses shared by other CrowdSec users, blocked before they reach you.</div><div>${comm.map(([k, v]) => `<div class="kv"><span>${e(k)}</span><span class="muted">${num(v)}</span></div>`).join('')}</div>`, {style: 'flex:1 1 280px'})}
</div>
${card('Attack history', 'Every alert CrowdSec raised', tbl([{h: 'Time', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'Address', f: x => ipl(x.ip) + `<div class="muted small">${e(x.country)} · ${e(x.owner)}</div>`}, {h: 'What it was doing', f: x => e(x.why) + `<div class="muted small">${e(x.scenario)}</div>`}, {h: 'Events', r: 1, f: x => num(x.events)}, {h: 'State', f: x => x.active ? '<span class="pill ok">Banned</span>' : '<span class="muted">Expired</span>'}], d.alerts, 'No alerts yet.'), {flush: true, style: 'flex:none'})}`;
};
V.ip = async r => {
  const d = await api('ip', {ip: r.arg}), act = (h, l) => `<button class="btn ${h === 24 ? 'pri' : ''}" data-act='${e(JSON.stringify({action: 'ban', ip: d.ip, hours: h, reason: 'banned from investigation'}))}' data-confirm="Ban ${e(d.ip)} for ${l}?">Ban ${l}</button>`;
  return `<div class="row" style="align-items:flex-end;justify-content:space-between"><div><div class="muted">Investigating an outside address</div><h1 class="verdict mono" style="font-size:30px">${e(d.ip)} ${d.banned ? `<span class="pill ok">Banned · ${left(d.until)}</span>` : d.own ? '<span class="pill info">One of yours</span>' : '<span class="pill anomaly">Not banned</span>'}</h1>
<div class="muted">${e(d.owner || 'Unknown network')} · ${e(d.country)}${d.total.first ? ' · first seen ' + when(d.total.first) + ' · last seen ' + ago(d.total.last) : ''}</div></div>
<div class="chips">${d.own ? '' : d.banned ? unbanBtn(d.ip) : banBox(d.ip, 'banned from investigation')}<a class="btn ghost" rel="noreferrer noopener" target="_blank" href="https://www.abuseipdb.com/check/${e(d.ip)}">Reputation lookup ↗</a></div></div>
<div class="card" style="flex:none"><div class="bd"><div style="font-size:16px">${e(d.summary)}</div>${d.total.n ? bars(d.series) : ''}</div></div>
${d.items.length ? `<section class="card" style="flex:none"><div class="bd flush">${d.items.map(itemRow).join('')}</div></section>` : ''}
<div class="row">
${card('What it asked your domains for', `${num(d.total.n)} requests`, tbl([{h: 'Domain', f: x => e(x.host)}, {h: 'Page', c: 'clip', t: x => x.path, f: x => `<span class="mono">${e(x.path || '/')}</span><div class="muted small">${e(x.why)}</div>`}, {h: 'Result', f: x => `<span class="${x.status < 400 ? 'amber b' : 'muted'} nowrap">${e(x.outcome)} (${x.status})</span>`}, {h: 'Times', r: 1, f: x => num(x.n)}], d.paths, 'No web requests from this address.'), {flush: true, style: 'flex:2 1 520px'})}
${card('Ports it knocked on', 'Dropped at the gateway', tbl([{h: 'Service', f: x => e(x.port) + ` <span class="muted">${e(x.proto)}</span>`}, {h: 'Times', r: 1, f: x => num(x.n)}, {h: 'Last', f: x => `<span class="muted nowrap">${ago(x.last)}</span>`}], d.fw, 'No firewall drops from this address.'), {flush: true, style: 'flex:1 1 300px'})}
</div>
<div class="row">
${card('CrowdSec verdicts', '', tbl([{h: 'Time', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'What', f: x => e(x.why) + `<div class="muted small">${e(x.scenario)} · ${num(x.events)} events</div>`}, {h: 'State', f: x => x.active ? '<span class="pill ok">Banned</span>' : '<span class="muted">Expired</span>'}], d.alerts, 'CrowdSec has raised nothing on this address.'), {flush: true})}
${card('Your devices that contacted it', 'Outbound connections to this address', tbl([{h: 'Device', f: x => devl(x.mac, x.name)}, {h: 'As', f: x => e(x.domain || '') + `<div class="muted small">port ${e(x.ports)}</div>`}, {h: 'Data', r: 1, f: x => bytes(x.b)}, {h: 'Last', f: x => `<span class="muted nowrap">${ago(x.last)}</span>`}], d.inside, 'None of your devices contacted this address.'), {flush: true})}
${card('Connections it made that were let in', '', tbl([{h: 'Time', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'Reached', f: x => `${e(x.dst_ip)} port ${x.dst_port} <span class="muted">${e(x.service)}</span>`}, {h: 'Data', r: 1, f: x => bytes(x.bytes)}, {h: '', f: x => x.action === 'blocked' ? 'Blocked' : 'Allowed'}], d.inbound, 'None.'), {flush: true})}
</div>
${card('Every request, in order', 'Newest first, up to 300', tbl([{h: 'Time', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'Domain', f: x => e(x.host)}, {h: 'Request', c: 'clip', t: x => x.uri, f: x => `<span class="mono">${e(x.method)} ${e(x.uri)}</span><div class="muted small">${e(x.why)}</div>`}, {h: 'Result', f: x => `<span class="${x.status < 400 ? 'amber b' : 'muted'} nowrap">${e(x.outcome)} (${x.status})</span>`}, {h: 'Sent to', f: x => `<span class="muted mono">${e(x.upstream)}</span>`}, {h: 'Client', c: 'clip', t: x => x.ua, f: x => `<span class="muted">${e(x.ua)}</span>`}], d.reqs, 'No web requests.'), {flush: true, style: 'flex:none'})}`;
};
V.item = async r => {
  const d = await api('item', {id: r.arg}); if (d.error) return `<div class="empty">${e(d.error)} <a href="#/home">Back to Home</a></div>`;
  const it = d.item, x = d.explain, ip = it.stype === 'ip', S = d.stats || {}, D = d.dest; PROMPT = d.prompt || '';
  const tl = card('Timeline', 'Everything recorded, newest first', tbl([{h: 'When', f: t => `<span class="muted nowrap">${when(t[0])}</span>`}, {h: 'Seen by', f: t => `<span class="muted nowrap">${e(t[1])}</span>`}, {h: 'What happened', f: t => e(t[2])}, {h: 'Result', f: t => `<span class="${t[4] === 'bad' ? 'red b' : t[4] === 'warn' ? 'amber b' : 'muted'} nowrap">${e(t[3])}</span>`}], d.timeline, 'Nothing else recorded.'), {flush: true, style: 'flex:none'});
  const numbers = ip
    ? `<div class="stats">${stat(num(S.n), 'web requests in 7 days')}${stat(num(S.ok), 'got a real answer', S.ok ? 'amber' : '')}${stat(num(S.bad), 'refused or not found')}${stat(num(S.hosts), 'of your domains tried')}${stat(num(S.knocks), `port knocks on ${num(S.ports)} ports`)}</div>`
    : D ? `<div class="stats">${stat(num(D.n), 'connections to it')}${stat(bytes(D.up), 'sent to it', D.up > 5e7 ? 'amber' : '')}${stat(bytes(D.down), 'received from it')}${stat(num(d.others.length), 'other devices that also use it')}${stat(D.first ? when(D.first) : '—', 'first contact')}</div>` : '';
  const body = ip ? `
${card('What it actually got', d.answered.length ? 'Requests your servers answered' : '', tbl([{h: 'When', f: t => `<span class="muted nowrap">${when(t.ts)}</span>`}, {h: 'Domain', f: t => e(t.host)}, {h: 'Request', c: 'clip', t: t => t.uri, f: t => `<span class="mono">${e(t.method)} ${e(t.uri)}</span><div class="muted small">${e(t.why)}</div>`}, {h: 'Answer', f: t => `<span class="amber b nowrap">${t.status} · ${bytes(t.bytes)}</span>`}, {h: 'Served by', f: t => `<span class="muted mono">${e(t.upstream)}</span>`}], d.answered, 'Nothing. No request from this address got a real answer.'), {flush: true, style: 'flex:none'})}
<div class="row">
${card('What it was after', 'Grouped by purpose', tbl([{h: 'Purpose', f: t => `<span class="b">${e(t.why.charAt(0).toUpperCase() + t.why.slice(1))}</span><div class="muted small mono">${t.eg.map(e).join(' · ')}</div>`}, {h: 'Requests', r: 1, f: t => num(t.n)}, {h: 'Answered', r: 1, f: t => t.ok ? `<span class="amber b">${num(t.ok)}</span>` : '0'}], d.goals, 'It sent no web requests.'), {flush: true, style: 'flex:2 1 460px'})}
${card('Which of your domains', '', tbl([{h: 'Domain', f: t => `<a style="color:var(--text)" href="${href('proxy', {all: 1, ip: d.ip, host: t.host})}">${e(t.host)}</a><div class="muted small mono">${e(t.upstream || 'not forwarded to any server')}</div>`}, {h: 'Requests', r: 1, f: t => num(t.n)}, {h: 'Answered', r: 1, f: t => t.ok ? `<span class="amber b">${num(t.ok)}</span>` : '0'}, {h: 'Login refused', r: 1, f: t => num(t.auth)}], d.targets, 'None.'), {flush: true, style: 'flex:2 1 420px'})}
</div>
<div class="row">
${card('Ports it knocked on', 'All dropped at the gateway', tbl([{h: 'Service', f: t => e(t.port) + ` <span class="muted">${e(t.proto)}</span>`}, {h: 'Times', r: 1, f: t => num(t.n)}, {h: 'Last', f: t => `<span class="muted nowrap">${ago(t.last)}</span>`}], d.fw, 'No port knocks.'), {flush: true})}
${card('Connections that were let in', 'Through ports you have opened', tbl([{h: 'Reached', f: t => e(t.who) + `<div class="muted small">${e(t.port)}</div>`}, {h: 'Times', r: 1, f: t => num(t.n)}, {h: 'Data', r: 1, f: t => bytes(t.b)}, {h: '', f: t => t.action === 'blocked' ? '<span class="pill ok">Blocked</span>' : '<span class="pill anomaly">Let in</span>'}], d.inbound, 'None recorded.'), {flush: true})}
${card('Your devices that contacted it', '', tbl([{h: 'Device', f: t => devl(t.mac, t.name)}, {h: 'Data', r: 1, f: t => bytes(t.b)}, {h: 'Last', f: t => `<span class="muted nowrap">${ago(t.last)}</span>`}], d.inside, 'None. Nothing inside your home talked to it.'), {flush: true})}
${card('Software it used', 'What it claimed to be', tbl([{h: 'Client', c: 'clip', t: t => t.ua, f: t => e(t.ua || '(blank)')}, {h: 'Requests', r: 1, f: t => num(t.n)}], d.tools, 'No web requests.'), {flush: true})}
</div>` : `
${D ? `<div class="row">
${card('The new destination', '', `<div><div class="kv"><span class="muted">Owner</span><span class="b">${e(D.owner)}</span></div><div class="kv"><span class="muted">Country</span><span>${e(D.country)}</span></div><div class="kv"><span class="muted">Site names it asked for</span><span>${e(D.domains.split(',').filter(Boolean).slice(0, 5).join(', ') || 'none, address only')}</span></div><div class="kv"><span class="muted">Ports</span><span>${e(D.ports)}</span></div><div class="kv"><span class="muted">Service</span><span>${e(D.services || 'not identified')}</span></div><div class="kv"><span class="muted">Different addresses</span><span>${num(D.ips)}</span></div><div class="kv"><span class="muted">Blocked by firewall</span><span>${num(D.blocked)}</span></div></div>`)}
${card('Other devices that talk to it', 'Familiar destinations are less worrying', tbl([{h: 'Device', f: t => devl(t.mac, t.name) + `<div class="muted small">${e(t.net)}</div>`}, {h: 'Data', r: 1, f: t => bytes(t.b)}, {h: 'Since', f: t => `<span class="muted nowrap">${when(t.first)}</span>`}], d.others, 'No other device in your home talks to this owner.'), {flush: true})}
</div>` : ''}
<div class="row">
${card('What this device normally talks to', 'For comparison', tbl([{h: 'Owner', f: t => e(t.who) + `<div class="muted small">${e(t.country)}</div>`}, {h: 'Data', r: 1, f: t => bytes(t.b)}, {h: 'Connections', r: 1, f: t => num(t.n)}, {h: 'Since', f: t => `<span class="muted nowrap">${when(t.first)}</span>`}], d.usual, 'Nothing recorded yet.'), {flush: true, style: 'flex:2 1 420px'})}
${card('Site lookups around that time', '30 minutes either side', tbl([{h: 'When', f: t => `<span class="muted nowrap">${when(t.ts)}</span>`}, {h: 'Name', f: t => e(t.domain)}, {h: '', f: t => t.blocked ? '<span class="pill ok">Blocked</span>' : ''}], d.dns, 'None visible. This device does not use AdGuard for lookups.'), {flush: true})}
</div>`;
  return `<div class="row" style="align-items:flex-end;justify-content:space-between"><div style="display:flex;flex-direction:column;gap:6px;min-width:0;flex:999 1 480px"><div class="muted"><a href="#/home">Home</a> / Alert</div>
<div class="chips"><span class="pill info">${e(it.label)}</span>${tonePill(it)}<span class="muted small">raised ${when(it.ts)} · ${itemMeta(it)}</span></div>
<h1 class="verdict" style="font-size:27px">${e(it.headline)}</h1>${factList(it.facts)}</div>
<div class="chips">${itemActs(it)}${ip && !d.banned && !d.own && it.status !== 'open' ? banBox(d.ip, it.label) : ''}${d.prompt ? `<a class="btn" rel="noreferrer noopener" target="_blank" href="https://claude.ai/new?q=${u(d.prompt)}" title="Opens a new Claude chat with this alert's details filled in. Nothing is sent until you press send.">Ask Claude ↗</a><a class="btn" rel="noreferrer noopener" target="_blank" href="https://chatgpt.com/?q=${u(d.prompt)}${d.chatgpt_model ? '&model=' + u(d.chatgpt_model) : ''}" title="Opens a new ChatGPT chat with this alert's details. ChatGPT may send the question as soon as the page opens.">Ask ChatGPT ↗</a><button class="btn ghost" data-copy="1" title="Copy the same question to paste into any assistant">Copy question</button>` : ''}<a class="btn" href="#/${it.stype}/${e(it.subject)}">${ip ? 'Full history of this address' : 'Everything this device does'}</a>${ip ? `<a class="btn ghost" rel="noreferrer noopener" target="_blank" href="https://www.abuseipdb.com/check/${e(d.ip)}">Reputation lookup ↗</a>` : ''}</div></div>
<div class="row">
${card('What happened', '', `<div style="font-size:15px">${e(x.what)}</div>`, {style: 'flex:2 1 420px'})}
${card('How serious is it', `<span class="pill ${x.level === 'low' ? 'ok' : 'anomaly'}">${x.level === 'low' ? 'Low' : 'Worth a look'}</span>`, `<div style="font-size:15px">${e(x.serious)}</div>`, {style: 'flex:1 1 300px'})}
${card('What to do', '', `<ol style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:8px;font-size:15px">${x.advice.map(a => `<li>${e(a)}</li>`).join('')}</ol>`, {style: 'flex:1 1 300px'})}
</div>
${numbers ? `<div class="card" style="flex:none"><div class="bd">${numbers}</div></div>` : ''}
${body}
${tl}
${d.related.length ? card('Other alerts about the same ' + (ip ? 'address' : 'device'), '', d.related.map(itemRow).join(''), {flush: true, style: 'flex:none'}) : ''}
${card('Technical details', 'For looking things up elsewhere', `<div>${d.tech.map(t => `<div class="kv"><span class="muted">${e(t[0])}</span><span class="mono" style="text-align:right;overflow-wrap:anywhere">${e(t[1])}</span></div>`).join('')}</div>`, {style: 'flex:none'})}`;
};
V.gateway = async () => {
  const d = await api('gateway'); if (d.error) return `<h1 class="verdict" style="font-size:26px">Gateway</h1><div class="note">${e(d.error)} <a href="#/setup?step=1">Open the walkthrough</a></div>`;
  const g = d.geo, st = d.state || {};
  if (!GEO) GEO = new Set(g.countries);
  const dirty = GEO.size !== g.countries.length || g.countries.some(c => !GEO.has(c));
  const modeTxt = {off: 'Off', in: 'Inbound only', both: 'Inbound and outbound', unknown: 'Unknown'}[g.mode];
  const mb = (m, l, t) => `<button class="btn ${g.mode === m && !dirty ? 'pri' : ''}" data-geo="${m}" title="${t}">${l}</button>`;
  const act = (o, l, c, cls) => `<button class="btn sm ${cls || ''}" data-act='${e(JSON.stringify(o))}'${c ? ` data-confirm="${e(c)}"` : ''}>${l}</button>`;
  const names = Object.fromEntries(d.countries.map(c => [c.cc, c.name]));
  return `<h1 class="verdict" style="font-size:26px">Gateway: blocking at the edge of your network</h1>
<div class="note">Everything here is enforced by the UniFi gateway itself, before traffic reaches any device or the reverse proxy.${st.error ? ` <span class="red b">Last update of the gateway failed: ${e(st.error)}</span>` : ''}</div>
${card('Country blocking', `Now: <span class="b" style="color:var(--text)">${modeTxt}</span>${g.countries.length ? ' · ' + g.countries.length + ' countries' : ''}`, `
<div class="muted">Tick the countries to block, then choose how. <span class="b" style="color:var(--text)">Inbound only</span> stops them reaching you. <span class="b" style="color:var(--text)">Inbound and outbound</span> also stops your devices reaching them, which can break apps and smart devices that use servers there. Your own country (${e(d.home)}) cannot be selected.</div>
<div class="chips">${mb('in', 'Block inbound only', 'Stop the ticked countries from connecting to you')}${mb('both', 'Block inbound and outbound', 'Also stop your devices from connecting to the ticked countries')}${mb('off', 'Turn off', 'Stop blocking by country')}<span class="muted small">${GEO.size} ticked${dirty ? ' · <span class="amber b">not applied yet</span>' : ''}</span>
<button class="btn ghost sm" data-geopick="top">Tick the 10 biggest sources</button><button class="btn ghost sm" data-geopick="none">Clear ticks</button></div>
${g.countries.length ? `<div class="chips"><span class="muted small">Blocked now:</span>${g.countries.map(c => `<span class="chip">${e(names[c] || c)}</span>`).join('')}</div>` : ''}
${tbl([{h: 'Block', f: c => `<input type="checkbox" data-cc="${e(c.cc)}" aria-label="Block ${e(c.name)}" ${GEO.has(c.cc) ? 'checked' : ''} style="width:18px;height:18px">`}, {h: 'Country', f: c => e(c.name) + (g.countries.includes(c.cc) ? ' <span class="pill ok">Blocked</span>' : '')}, {h: 'Attempts against you', r: 1, f: c => c.n ? num(c.n) : '<span class="muted">0</span>'}, {h: 'Data your devices exchanged with it', r: 1, f: c => c.out ? `<span class="${c.out > 1e7 ? 'amber b' : ''}">${bytes(c.out)}</span>` : '<span class="muted">none</span>'}], d.countries)}`, {style: 'flex:none'})}
<div class="row">
${card('Block lists', `${num(st.members || 0)} addresses and ranges on the gateway${st.synced ? ' · updated ' + ago(st.synced) : ''}`, `<div class="muted">Public lists of known-bad networks, refreshed daily. They block new inbound connections only, to the gateway and to ${e((st.zones || []).filter(z => z !== 'Gateway').join(', ') || 'your forwarded ports')}.</div>
${tbl([{h: 'List', f: l => `<span class="b">${e(l.name)}</span><div class="muted small">${e(l.about || '')}</div>${l.error ? `<div class="red small">Could not update: ${e(l.error)}</div>` : ''}`}, {h: 'Entries', r: 1, f: l => l.enabled ? (l.count ? num(l.count) : 'loading…') : '<span class="muted">—</span>'}, {h: 'Updated', f: l => `<span class="muted nowrap">${l.enabled && l.updated ? ago(l.updated) : ''}</span>`},
  {h: '', f: l => (l.enabled ? '<span class="pill ok">On</span> ' + act({action: 'gw-list', id: l.id, enabled: false}, 'Turn off') : act({action: 'gw-list', id: l.id, enabled: true}, 'Turn on', '', 'pri')) + (l.builtin ? '' : ' ' + act({action: 'gw-list-remove', id: l.id}, 'Remove', 'Remove this list?'))}], d.lists)}
<form id="listform" class="chips"><input type="text" name="name" placeholder="Name for a list of your own" aria-label="List name" required style="flex:1 1 160px"><input type="text" name="url" placeholder="https://… plain-text list of addresses" aria-label="List address" required style="flex:2 1 260px"><button class="btn">Add list</button>${act({action: 'gw-refresh'}, 'Update all now')}</form>`, {style: 'flex:2 1 560px'})}
${card('Bans sent to the gateway', `${d.bans.length} address${d.bans.length === 1 ? '' : 'es'}`, `<div class="muted">Bans normally apply at the reverse proxy only. Sending one here also drops that address at the gateway, on every port. Nothing is sent unless you choose to; a ban leaves the gateway when it expires or you unban it.</div>
${d.pending ? `<div>${act({action: 'gw-ban-all'}, `Send all ${d.pending} current ban${d.pending === 1 ? '' : 's'} to the gateway`, `Block ${d.pending} banned address${d.pending === 1 ? '' : 'es'} at the gateway as well?`, 'pri')}</div>` : '<div class="muted small">Every current ban is already at the gateway, or there are no bans.</div>'}
${tbl([{h: 'Address', f: x => ipl(x.ip) + `<div class="muted small">${e(x.country)} · ${e(x.owner)}</div>`}, {h: 'Remaining', f: x => `<span class="nowrap">${left(x.until)}</span>`}, {h: '', f: x => act({action: 'gw-unban', ip: x.ip}, 'Remove from gateway')}], d.bans, 'No bans have been sent to the gateway.')}`, {style: 'flex:1 1 360px'})}
</div>`;
};
// ---------- shared form pieces ----------
const fInp = (n, label, o) => `<label style="display:flex;flex-direction:column;gap:4px;min-width:0;flex:${(o && o.w) || '1 1 180px'}"><span class="muted small">${e(label)}</span><input type="${(o && o.pw) ? 'password' : 'text'}" name="${n}" value="${e((o && o.v) ?? '')}" placeholder="${e((o && o.ph) || '')}" autocomplete="${(o && o.pw) ? 'new-password' : 'off'}"></label>`;
const fBtns = (t, sv, label) => `<div class="chips">${t ? `<button class="btn" name="go" value="${t}">Test</button>` : ''}<button class="btn pri" name="go" value="${sv}">${label || 'Test and save'}</button><span class="cmsg muted" role="status"></span></div>`;
const fSaved = t => t ? `••••••••${t === true ? '' : t}  (saved; type to replace)` : 'not set';
const codeBox = t => `<div class="chips"><code class="mono" style="flex:1 1 400px;background:#0B0F13;border:1px solid var(--line2);border-radius:8px;padding:10px 12px;overflow-wrap:anywhere;white-space:pre-wrap">${e(t)}</code><button class="btn" data-copytext="${e(t)}">Copy</button></div>`;
const tick = (ok, yes, no) => ok ? `<span class="pill ok">${yes || 'Connected'}</span>` : `<span class="pill info">${no || 'Not yet'}</span>`;
const dockerShip = (I, kind, path) => `docker run -d --name hc-shipper --restart unless-stopped \\\n  -v ${path}:/logs:ro \\\n  -e HC_URL=${I.base} -e HC_TOKEN=${I.token} \\\n  -e HC_KIND=${kind} -e HC_GLOB='/logs/*.log' \\\n  homecommand python3 /app/portal-shipper.py`;

// ---------- first-run walkthrough ----------
const STEPS = ['Welcome', 'Gateway', 'Your home', 'Reverse proxy', 'DNS filter', 'Attack blocking', 'Gateway feeds', 'Finish'];
V.setup = async r => {
  const [S, C] = await Promise.all([api('settings'), api('connections')]), st = S.status, U = C.unifi, I = C.install;
  if (r.q.step !== undefined) STEP = Math.max(0, Math.min(STEPS.length - 1, Number(r.q.step) || 0));
  const nav = (back, next, nextLabel) => `<div class="chips" style="justify-content:space-between;margin-top:6px"><span>${back !== null ? `<a class="btn ghost" href="#/setup?step=${back}">Back</a>` : ''}</span><span class="chips">${next !== null ? `<a class="btn ${nextLabel ? 'pri' : ''}" href="#/setup?step=${next}">${nextLabel || 'Skip for now'}</a>` : ''}</span></div>`;
  const proxyKind = S.proxy_type, logPath = {npm: '/path/to/npm/data/logs', traefik: '/var/log/traefik', caddy: '/var/log/caddy', nginx: '/var/log/nginx'}[proxyKind] || '/path/to/logs';
  const bodies = [
    // 0 welcome
    () => `<div style="font-size:15px">This walkthrough connects Home Command to your network, one piece at a time. You can skip any step and come back later from the Settings page.</div>
<div><div class="kv"><span>1. Your UniFi gateway</span><span class="muted">needed · devices, traffic, internet speed, blocking</span></div><div class="kv"><span>2. Your home</span><span class="muted">which network holds smart devices</span></div><div class="kv"><span>3. Your reverse proxy</span><span class="muted">who touches your domains</span></div><div class="kv"><span>4. Your DNS filter</span><span class="muted">sites your devices look up</span></div><div class="kv"><span>5. CrowdSec</span><span class="muted">optional · automatic and manual bans</span></div><div class="kv"><span>6. Gateway log and NetFlow</span><span class="muted">dropped connections, threat alerts, packet detail</span></div></div>
<div class="muted small">Have ready: an admin login for your UniFi gateway, and command-line access to the machine that runs your reverse proxy.</div>${nav(null, 1, 'Start')}`,
    // 1 gateway
    () => `<div class="chips">${tick(st.unifi)}${st.unifi_error && !st.unifi ? `<span class="red small">${e(st.unifi_error)}</span>` : ''}</div>
<div>Home Command reads your devices, their connections and your internet speed from the gateway, and uses it to block devices, countries and addresses when you ask.</div>
<div class="muted small"><span class="b" style="color:var(--text)">Recommended: a local admin account.</span> In UniFi, go to Settings → Admins &amp; Users, add an admin, choose "Restrict to local access only", and give it full Network access. Leave two-step sign-in off for this account.<br><span class="b" style="color:var(--text)">Or an API key:</span> in UniFi Network, Settings → Control Plane → Integrations → Create API Key.</div>
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="chips">${fInp('url', 'Gateway address', {w: '1 1 320px', v: U.url, ph: 'https://192.168.1.1'})}</div>
<div class="chips"><label class="chip"><input type="radio" name="mode" value="account" ${U.mode !== 'key' ? 'checked' : ''}> Local admin account</label><label class="chip"><input type="radio" name="mode" value="key" ${U.mode === 'key' ? 'checked' : ''}> API key</label></div>
<div class="chips">${fInp('username', 'Local account name', {v: U.username})}${fInp('password', 'Local account password', {pw: 1, ph: U.mode === 'account' && U.has_password ? fSaved(true) : ''})}</div>
<div class="chips">${fInp('key', 'API key', {pw: 1, w: '1 1 320px', ph: U.mode === 'key' && U.key_tail ? fSaved(U.key_tail) : ''})}</div>
${fBtns('conn-test', 'conn-save')}</form>${nav(0, 2, st.unifi ? 'Next' : '')}`,
    // 2 home
    () => `<div>Tell Home Command about your home so it knows what is normal.</div>
<form class="cform" style="display:flex;flex-direction:column;gap:14px">
<div><div class="lbl">Which networks hold smart-home devices?</div><div class="muted small">Cameras, plugs, TVs, speakers. Home Command learns what each of these normally talks to and alerts you when one contacts somewhere new.</div>
<div class="chips" style="margin-top:8px">${S.networks.length ? S.networks.map(n => `<label class="chip"><input type="checkbox" name="iot:${e(n)}" ${S.iot_networks.includes(n) ? 'checked' : ''}> ${e(n)}</label>`).join('') : '<span class="muted">Connect the gateway first and your networks will be listed here.</span>'}</div></div>
<div class="chips">${fInp('own_ips', 'Outside addresses that are yours and must never be banned (optional, comma separated)', {w: '1 1 100%', v: S.own_ips.join(', '), ph: 'your office, a server you rent, a relative\'s house'})}</div>
<div class="chips">${fInp('home_lat', 'Home latitude (optional)', {v: S.home.lat ?? '', ph: 'e.g. 42.3'})}${fInp('home_lon', 'Home longitude (optional)', {v: S.home.lon ?? '', ph: 'e.g. -83.0'})}</div>
<div class="muted small">The location only places the "Home" dot on the attack map. Left blank, it sits in the middle of your country. Your current public address${S.wan.ip ? ` (${e(S.wan.ip)})` : ''} is protected automatically.</div>
${fBtns('', 'settings-save', 'Save')}</form>${nav(1, 3, 'Next')}`,
    // 3 reverse proxy
    () => `<div class="chips">${tick(st.proxy, 'Receiving requests')}</div>
<div>Home Command reads your reverse proxy's access log to show who touches your domains and what they ask for. A small helper on the proxy machine sends new log lines here.</div>
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="chips"><label style="display:flex;flex-direction:column;gap:4px;flex:0 1 320px"><span class="muted small">Which reverse proxy do you use?</span><select name="proxy_type" class="btn">${Object.entries(S.proxy_names).map(([k, v]) => `<option value="${k}" ${k === proxyKind ? 'selected' : ''}>${e(v)}</option>`).join('')}</select></label></div>
${fBtns('', 'settings-save', 'Save choice')}</form>
${proxyKind === 'none' ? '<div class="muted">Nothing to install. The Reverse proxy page will stay empty.</div>' : `
<div class="lbl">Option A: the proxy runs directly on a Linux machine or container</div><div class="muted small">Run this as root on that machine. If its log is somewhere else, put <span class="mono">${proxyKind === 'npm' ? 'LOG_DIR=/your/path/data/logs' : 'LOG=/your/path/access.log'}</span> in front of <span class="mono">sh</span>.</div>${codeBox(I[proxyKind])}
<div class="lbl">Option B: the proxy runs in Docker</div><div class="muted small">Run the helper as a container that can read the folder where the proxy writes its access log. Replace the first path with that folder on the Docker host.</div>${codeBox(dockerShip(I, proxyKind, logPath))}
${proxyKind === 'traefik' ? '<div class="muted small">Traefik does not write an access log by default. Add <span class="mono">--accesslog=true --accesslog.filepath=/var/log/traefik/access.log --accesslog.format=json</span> to its command, and keep the User-Agent header with <span class="mono">--accesslog.fields.headers.names.User-Agent=keep</span>.</div>' : ''}
${proxyKind === 'caddy' ? '<div class="muted small">Caddy only logs sites that have a <span class="mono">log</span> block. Add <span class="mono">log { output file /var/log/caddy/access.log }</span> to each site, or once in a snippet you import.</div>' : ''}
${proxyKind === 'nginx' ? '<div class="muted small">The standard "combined" log format does not record which site was asked for, so every request shows under one name. Home Command still shows who asked for what.</div>' : ''}
<div class="muted small">These commands contain this portal's feed password. They only work from inside your network.</div>`}${nav(2, 4, st.proxy ? 'Next' : '')}`,
    // 4 dns
    () => `<div class="chips">${tick(st.dns, 'Receiving lookups')}</div>
<div>Connect AdGuard Home or Pi-hole to see which sites your devices look up and what gets blocked.</div>
${C.dns.length ? `<div>${C.dns.map(x => `<div class="kv"><span>${e(x.name)} <span class="muted small mono">${e(x.url)}</span></span><span>${x.err ? `<span class="red">${e(x.err)}</span>` : 'Connected'}</span></div>`).join('')}</div>` : ''}
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="chips"><label style="display:flex;flex-direction:column;gap:4px"><span class="muted small">Type</span><select name="type" class="btn"><option value="adguard">AdGuard Home</option><option value="pihole">Pi-hole (version 6 or later)</option></select></label>${fInp('name', 'Short name', {w: '1 1 160px', ph: 'adguard'})}${fInp('url', 'Its web address', {w: '2 1 260px', ph: 'http://192.168.1.53'})}</div>
<div class="chips">${fInp('username', 'User name (AdGuard Home only)')}${fInp('password', 'Password', {pw: 1})}</div>
${fBtns('dns-test', 'dns-save')}</form>
<div class="muted small">Have more than one? Save the first, then fill the form in again. If you would rather not give a login, the Connections page has a log-file method instead.</div>${nav(3, 5, st.dns ? 'Next' : '')}`,
    // 5 crowdsec
    () => `<div class="chips">${tick(st.crowdsec)}<span class="pill info">Optional</span></div>
<div>CrowdSec watches your reverse proxy's log, bans attackers automatically, and is what the portal's Ban and Unban buttons control. Without it, you can still block at the gateway from the Gateway page.</div>
<div class="muted small">On the machine where CrowdSec runs, create a login for the portal and note the password you choose:</div>${codeBox("cscli machines add homecommand --password 'choose-a-password'")}
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="chips">${fInp('url', 'CrowdSec address', {w: '1 1 320px', v: C.crowdsec.url, ph: 'http://192.168.1.20:8080'})}</div>
<div class="chips">${fInp('machine', 'Machine name', {v: C.crowdsec.machine, ph: 'homecommand'})}${fInp('password', 'Machine password', {pw: 1, ph: C.crowdsec.has_password ? fSaved(true) : ''})}</div>
${fBtns('cs-test', 'cs-save')}</form>
<div class="muted small">CrowdSec must accept connections from this portal: in its <span class="mono">config.yaml</span>, <span class="mono">api.server.listen_uri</span> should be <span class="mono">0.0.0.0:8080</span>, not 127.0.0.1.</div>${nav(4, 6, st.crowdsec ? 'Next' : '')}`,
    // 6 feeds
    () => { const ip = (S.lan_url.match(/\/\/([^:/]+)/) || [])[1] || 'this portal'; return `<div>Two feeds come straight from the gateway. Both are switched on in UniFi Network.</div>
<div class="lbl">Gateway log ${tick(st.syslog, 'Receiving')}</div>
<div class="muted small">Gives you dropped connections on the Perimeter page and UniFi's threat detections as alerts.</div>
<ol style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:6px"><li>In UniFi Network, open Settings → CyberSecure → Traffic Logging.</li><li>Turn on activity logging to a remote (SIEM / syslog) server.</li><li>Server address <span class="mono b">${e(ip)}</span>, port <span class="mono b">${st.syslog_port || 5514}</span>.</li><li>Include security detections and firewall logs. For firewall rules you care about, turn on logging in each rule.</li></ol>
<div class="lbl" style="margin-top:8px">NetFlow ${tick(st.netflow, 'Receiving')} <span class="pill info">Optional</span></div>
<div class="muted small">Adds packet counts and connection behaviour on the NetFlow page. It needs an Elasticsearch server to store the records; add that on the Connections page first${st.elastic ? ' (already added)' : ''}.</div>
<ol style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:6px"><li>In the same UniFi settings area, turn on NetFlow.</li><li>Version 10 (IPFIX), server <span class="mono b">${e(ip)}</span>, port <span class="mono b">${st.netflow_port}</span>.</li><li>Select the networks to export.</li></ol>
${S.lan_address || /^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(ip) ? '' : `<div class="note">This portal does not seem to know its address on your home network (it sees <span class="mono">${e(ip)}</span>), which is common in Docker. Set "Portal address on your network" on the Settings page so these instructions show the right address.</div>`}${nav(5, 7, 'Next')}`; },
    // 7 finish
    () => `<div style="font-size:15px">That's the essentials. What's connected:</div>
<div>${[['UniFi gateway', st.unifi], ['Reverse proxy log', st.proxy], ['DNS filter', st.dns], ['CrowdSec', st.crowdsec], ['Gateway log', st.syslog], ['NetFlow', st.netflow]].map(x => `<div class="kv"><span>${x[0]}</span><span>${tick(x[1], 'Working', 'Not connected')}</span></div>`).join('')}</div>
<div class="muted small">Smart-device "new destination" alerts stay quiet for the first ${S.learn_hours} hours while Home Command learns what is normal. Single sign-on, phone alerts, block lists and country blocking are on the Connections, Settings and Gateway pages.</div>
<form class="cform"><input type="hidden" name="setup_done" value="1"><div class="chips"><a class="btn ghost" href="#/setup?step=6">Back</a><button class="btn pri" name="go" value="settings-save" data-then="#/home">Finish and open Home Command</button><span class="cmsg muted" role="status"></span></div></form>`];
  return `<div style="max-width:860px;margin:0 auto;width:100%;display:flex;flex-direction:column;gap:18px">
<div class="chips" aria-label="Setup steps">${STEPS.map((n, i) => `<a class="chip ${i === STEP ? 'on' : ''}" href="#/setup?step=${i}">${i + 1}. ${n}</a>`).join('')}</div>
<section class="card" style="flex:none"><div class="hd"><h1 class="lbl">Step ${STEP + 1} of ${STEPS.length}: ${STEPS[STEP]}</h1></div><div class="bd" style="gap:14px">${bodies[STEP]()}</div></section></div>`;
};
V.settings = async () => {
  const S = await api('settings'), T = S.thresholds, K = S.retention_days;
  const save = l => fBtns('', 'settings-save', l || 'Save');
  return `<h1 class="verdict" style="font-size:26px">Settings</h1>
<div class="row">
${card('Your home', '', `<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div><div class="muted small">Networks that hold smart-home devices</div><div class="chips" style="margin-top:6px">${S.networks.map(n => `<label class="chip"><input type="checkbox" name="iot:${e(n)}" ${S.iot_networks.includes(n) ? 'checked' : ''}> ${e(n)}</label>`).join('') || '<span class="muted">No networks known yet.</span>'}</div></div>
<div class="chips">${fInp('own_ips', 'Outside addresses that are yours and must never be banned (comma separated)', {w: '1 1 100%', v: S.own_ips.join(', ')})}</div>
<div class="chips">${fInp('home_lat', 'Home latitude', {v: S.home.lat ?? '', ph: 'blank = middle of your country'})}${fInp('home_lon', 'Home longitude', {v: S.home.lon ?? ''})}</div>${save()}</form>`, {style: 'flex:1 1 460px'})}
${card('Alerts', '', `<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="chips">${fInp('learn_hours', 'Hours to learn a smart device before alerting on new destinations', {v: S.learn_hours})}</div>
<div class="chips">${fInp('probe_fails', 'Failed requests in 10 minutes that count as probing', {v: T.probe_fails})}${fInp('auth_fails', 'Refused logins in 10 minutes that count as password guessing', {v: T.auth_fails})}</div>
<div class="chips">${fInp('ntfy_url', 'Phone alerts: ntfy topic address (optional)', {w: '1 1 100%', v: S.ntfy_url, ph: 'https://ntfy.example.com/my-topic'})}</div>
<div class="muted small">Phone alerts use ntfy. Alert text is sent to whichever ntfy server you enter; a public server such as ntfy.sh will see it.</div>
<div class="chips"><button class="btn pri" name="go" value="settings-save">Save</button><button type="button" class="btn" data-act='${e(JSON.stringify({action: 'test-notify'}))}'>Send a test alert</button><span class="cmsg muted" role="status"></span></div></form>`, {style: 'flex:1 1 460px'})}
</div>
<div class="row">
${card('How long to keep records', 'Days', `<form class="cform" style="display:flex;flex-direction:column;gap:12px"><div class="chips">${fInp('keep_req', 'Reverse proxy requests', {v: K.req})}${fInp('keep_fw', 'Dropped connections', {v: K.fw})}${fInp('keep_flow', 'Device connections', {v: K.flow})}${fInp('keep_dns', 'Site lookups', {v: K.dns})}</div>${save()}</form>`, {style: 'flex:1 1 460px'})}
${card('This portal', '', `<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="chips"><label style="display:flex;flex-direction:column;gap:4px;flex:1 1 220px"><span class="muted small">Reverse proxy</span><select name="proxy_type" class="btn">${Object.entries(S.proxy_names).map(([k, v]) => `<option value="${k}" ${k === S.proxy_type ? 'selected' : ''}>${e(v)}</option>`).join('')}</select></label>${fInp('chatgpt_model', 'Model name for the Ask ChatGPT link (optional)', {v: S.chatgpt_model})}</div>
<div class="chips">${fInp('public_url', 'Public address of this portal, used in phone alerts (optional)', {w: '1 1 100%', v: S.public_url, ph: 'https://portal.example.com'})}</div>
<div class="chips">${fInp('lan_address', 'Portal address on your network, if it guesses wrong (now ' + S.lan_url + ')', {w: '1 1 100%', v: S.lan_address, ph: '192.168.1.50'})}</div>${save()}</form>`, {style: 'flex:1 1 460px'})}
</div>
${card('About', 'Version ' + e(S.version), `<div><div class="kv"><span>Setup walkthrough</span><a class="btn sm" href="#/setup?step=0">Run it again</a></div><div class="kv"><span>Country and network-owner lookups</span><span class="muted">${S.status.geo ? 'IP Geolocation by DB-IP (db-ip.com), CC BY 4.0, refreshed monthly' : 'Database not downloaded yet'}</span></div><div class="kv"><span>Passwords and sign-in</span><a href="#/connections">Connections page</a></div></div>`, {style: 'flex:none'})}`;
};
// ---------- traffic analytics ----------
const SERIES = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#0ca30c'], OTHERC = '#6B7684';
const SVCSLOT = {HTTPS: 0, HTTP: 1, 'UDP/443': 2};   // the usual three keep their colours whatever else is on screen
function svcColors(keys) {
  const used = new Set(), out = {};
  keys.forEach(k => { if (k.k in SVCSLOT) { out[k.k] = SERIES[SVCSLOT[k.k]]; used.add(SVCSLOT[k.k]); } });
  keys.forEach(k => { if (k.k === 'Other') out[k.k] = OTHERC; else if (!(k.k in out)) { let i = 0; while (used.has(i)) i++; used.add(i); out[k.k] = SERIES[i % SERIES.length]; } });
  return out;
}
const tipAttr = lines => ` data-tip="${e(lines.join('\n'))}"`;
function stackChart(S, col, unit) {
  const keys = S.keys.filter(k => k.total > 0), n = S.v[S.keys[0].k].length, tot = Array.from({length: n}, (_, i) => keys.reduce((a, k) => a + S.v[k.k][i], 0)), max = Math.max(1, ...tot);
  if (!keys.length) return '<div class="empty">No traffic in this period.</div>';
  const W = 760, H = 220, L = 58, B = 22, T = 8, pw = (W - L) / n, ph = H - B - T, y = v => T + ph - ph * v / max;
  const perSec = unit ? v => num(Math.round(v / S.step)) + ' ' + unit + '/s' : v => bpsT(v * 8 / S.step), amt = unit ? v => num(v) + ' ' + unit : bytes;
  let g = '';
  for (const f of [0, .5, 1]) g += `<line x1="${L}" x2="${W}" y1="${y(max * f).toFixed(1)}" y2="${y(max * f).toFixed(1)}" stroke="${f ? '#232A33' : '#3A4450'}" stroke-width="1"/><text x="${L - 8}" y="${(y(max * f) + 4).toFixed(1)}" text-anchor="end" fill="#A3ADBA" font-size="11">${f ? perSec(max * f) : '0'}</text>`;
  let bars = '';
  for (let i = 0; i < n; i++) {
    let acc = 0; const x = L + i * pw + 1, w = Math.max(1, pw - 2);
    for (const k of keys) { const v = S.v[k.k][i]; if (!v) continue; const h = ph * v / max; if (h >= 1.5) bars += `<rect x="${x.toFixed(1)}" y="${(y(acc + v) + 1).toFixed(1)}" width="${w.toFixed(1)}" height="${Math.max(.5, h - 1).toFixed(1)}" fill="${col[k.k]}"/>`; acc += v; }
    const lines = [when(S.start + i * S.step) + ' · ' + perSec(tot[i]) + ' average', ...keys.filter(k => S.v[k.k][i]).sort((p, q) => S.v[q.k][i] - S.v[p.k][i]).map(k => `${amt(S.v[k.k][i])}  ${k.name}`)];
    bars += `<rect x="${(L + i * pw).toFixed(1)}" y="${T}" width="${pw.toFixed(1)}" height="${ph}" fill="transparent" class="hit"${tipAttr(tot[i] ? lines : [when(S.start + i * S.step), 'No traffic'])}/>`;
  }
  return `<div class="hscroll"><svg viewBox="0 0 ${W} ${H}" style="width:100%;min-width:560px;height:auto" role="img" aria-label="Traffic over time, split by service. Peak ${perSec(max)}.">${g}${bars}<text x="${L}" y="${H - 5}" fill="#A3ADBA" font-size="11">${when(S.start)}</text><text x="${W}" y="${H - 5}" text-anchor="end" fill="#A3ADBA" font-size="11">now</text></svg></div>
<div class="legend">${keys.map(k => `<span><i style="background:${col[k.k]}"></i>${e(k.name)} <span class="muted">${amt(k.total)}</span></span>`).join('')}</div>`;
}
function sankeyChart(K, col, colByName) {
  if (!K.a.length) return '<div class="empty">No traffic in this period.</div>';
  const W = 900, H = 440, PADL = 190, PADR = 210, NW = 12, GAP = 6, X = [PADL, W / 2 - NW / 2, W - PADR - NW];
  const sum = (arr, i) => { const m = new Map(); arr.forEach(l => m.set(l[i], (m.get(l[i]) || 0) + l[2])); return m; };
  const cols = [sum(K.a, 0), sum(K.a, 1), sum(K.b, 1)], total = [...cols[1].values()].reduce((a, b) => a + b, 0) || 1;
  const order = m => [...m.entries()].sort((p, q) => (/^(Other|Everything)/.test(p[0]) - /^(Other|Everything)/.test(q[0])) || q[1] - p[1]);
  const pos = cols.map(m => { const list = order(m), scale = (H - 16 - GAP * (list.length - 1)) / total; let y = 8; const o = {}; list.forEach(([k, v]) => { const h = Math.max(2, v * scale); o[k] = {y, h, v, used: 0, used2: 0}; y += h + GAP; }); return o; });
  const band = (x0, y0, x1, y1, h, fill, tip) => { const m = (x0 + x1) / 2; return `<path d="M${x0},${y0.toFixed(1)} C${m},${y0.toFixed(1)} ${m},${y1.toFixed(1)} ${x1},${y1.toFixed(1)} L${x1},${(y1 + h).toFixed(1)} C${m},${(y1 + h).toFixed(1)} ${m},${(y0 + h).toFixed(1)} ${x0},${(y0 + h).toFixed(1)} Z" fill="${fill}" class="flowband"${tipAttr(tip)}/>`; };
  let out = '';
  const draw = (links, ci, key) => links.slice().sort((p, q) => q[2] - p[2]).forEach(l => {
    const s = pos[ci][l[0]], t = pos[ci + 1][l[1]]; if (!s || !t) return; const hs = s.h * l[2] / s.v, ht = t.h * l[2] / t.v, h = Math.max(1, Math.min(hs, ht));
    out += band(X[ci] + NW, s.y + s[key], X[ci + 1], t.y + t.used2, h, colByName[ci ? l[0] : l[1]] || OTHERC, [`${bytes(l[2])}  (${Math.round(100 * l[2] / total)}% of the total)`, `${l[0]} → ${l[1]}`]); s[key] += hs; t.used2 += ht;
  });
  draw(K.a, 0, 'used'); Object.values(pos[1]).forEach(o => { o.used2 = 0; }); draw(K.b, 1, 'used');
  const clip = (t, n) => t.length > n ? t.slice(0, n - 1) + '…' : t;
  cols.forEach((m, ci) => Object.entries(pos[ci]).forEach(([k, o]) => {
    const fill = ci === 1 ? (colByName[k] || OTHERC) : '#8A95A3', tx = ci === 0 ? X[0] - 8 : ci === 2 ? X[2] + NW + 8 : X[1] + NW / 2, anchor = ci === 0 ? 'end' : ci === 2 ? 'start' : 'middle';
    out += `<rect x="${X[ci]}" y="${o.y.toFixed(1)}" width="${NW}" height="${o.h.toFixed(1)}" rx="2" fill="${fill}"${tipAttr([`${bytes(o.v)}  (${Math.round(100 * o.v / total)}%)`, k])}/>`;
    if (ci !== 1 && o.h >= 9) out += `<text x="${tx}" y="${(o.y + o.h / 2 + 4).toFixed(1)}" text-anchor="${anchor}" fill="#E6E9EE" font-size="12">${e(clip(k, 28))}</text>`;
  }));
  return `<div class="hscroll"><svg viewBox="0 0 ${W} ${H}" style="width:100%;min-width:680px;height:auto" role="img" aria-label="Which devices use which services to reach which destinations">${out}</svg></div>
<div style="display:flex;justify-content:space-between" class="muted small"><span>Your devices</span><span>Service</span><span>Destination</span></div>`;
}
function matrixTable(M) {
  if (!M.length) return '<div class="empty">No traffic between your networks in this period.</div>';
  const nets = [...new Set(M.flatMap(m => [m.src_net, m.dst_net]))].sort(), by = Object.fromEntries(M.map(m => [m.src_net + '>' + m.dst_net, m])), max = Math.max(1, ...M.map(m => m.b));
  const RAMP = ['#0d366b', '#104281', '#184f95', '#1c5cab', '#256abf', '#2a78d6', '#3987e5'];
  return `<div class="hscroll"><table class="matrix"><thead><tr><th scope="col">From ↓ to →</th>${nets.map(n => `<th scope="col" class="r">${e(n)}</th>`).join('')}</tr></thead><tbody>${nets.map(a => `<tr><th scope="row">${e(a)}</th>${nets.map(b => { const m = by[a + '>' + b]; if (!m || !m.b) return '<td class="r muted">·</td>'; const i = Math.min(RAMP.length - 1, Math.floor(RAMP.length * Math.sqrt(m.b / max))); return `<td class="r" style="background:${RAMP[i]};color:#fff"${tipAttr([bytes(m.b), `${a} → ${b}`, num(m.n) + ' connections'])}>${bytes(m.b)}</td>`; }).join('')}</tr>`).join('')}</tbody></table></div>`;
}
V.traffic = async r => {
  const d = await api('traffic', r.q), q = r.q, T = d.total, add = o => href('traffic', Object.assign({}, q, o)), local = d.dir === 'local';
  const col = svcColors(d.series.keys), colByName = Object.fromEntries(d.series.keys.map(k => [k.name, col[k.k]]));
  const mx = (a, f) => Math.max(1, ...a.map(f || (x => x.b))), psum = d.protos.reduce((a, p) => a + (p.b || 0), 0) || 1;
  const sw = k => `<i class="sw" style="background:${col[k] || OTHERC}"></i>`;
  const labels = {mac: 'Device', svc: 'Service', to: 'Destination', cc: 'Country', net: 'Network'}, shown = Object.assign({}, q); if (q.mac) shown.mac = d.devname || q.mac; if (q.svc) shown.svc = d.svcname;
  const on = Object.keys(q).filter(k => labels[k]);
  return `<div class="row" style="align-items:center;justify-content:space-between"><h1 class="verdict" style="font-size:26px">Traffic: who talks to whom, and how</h1>
<div class="chips"><a class="chip ${local ? '' : 'on'}" href="${href('traffic', {})}">To the internet</a><a class="chip ${local ? 'on' : ''}" href="${href('traffic', {dir: 'local'})}">Inside your home</a></div></div>
${on.length ? `<div class="chips"><span class="muted">Showing only:</span>${on.map(k => { const rest = Object.assign({}, q); delete rest[k]; return `<a class="chip on" href="${href('traffic', rest)}" title="Remove this filter">${labels[k]}: ${e(shown[k])} ✕</a>`; }).join('')}<a class="chip" href="${href('traffic', local ? {dir: 'local'} : {})}">Clear all</a></div>` : '<div class="muted small">Click any device, service, destination or country to narrow every chart on this page to it.</div>'}
<div class="card" style="flex:none"><div class="bd"><div class="stats">${stat(bytes(T.b), 'exchanged')}${stat(bytes(T.up), 'sent')}${stat(bytes(T.down), 'received')}${stat(num(T.n), 'connections')}${stat(num(T.devs), 'devices')}${stat(num(T.dests), local ? 'devices reached' : 'destination owners')}${local ? '' : stat(num(T.ccs), 'countries')}</div></div></div>
${card('Traffic over time, by service', 'Hover a bar for the breakdown', stackChart(d.series, col), {style: 'flex:none'})}
<div class="row">
${card('Top talkers', 'Devices by data', tbl([{h: 'Device', f: x => `<a style="color:var(--text)" href="${add({mac: x.mac})}">${e(x.name || x.mac)}</a><div class="muted small">${e(x.net)}</div>`}, {h: 'Data', f: x => barc(x.b, mx(d.talkers), bytes(x.b))}, {h: 'Sent', r: 1, f: x => bytes(x.up)}, {h: 'Received', r: 1, f: x => bytes(x.down)}, {h: 'Reached', r: 1, f: x => num(x.dests)}], d.talkers), {flush: true, style: 'flex:1 1 460px'})}
${card('Top services', 'What the traffic is', tbl([{h: 'Service', f: x => `${sw(x.svc)}<a style="color:var(--text)" href="${add({svc: x.svc})}">${e(x.name)}</a>`}, {h: 'Data', f: x => barc(x.b, mx(d.services), bytes(x.b))}, {h: 'Connections', r: 1, f: x => num(x.n)}, {h: 'Devices', r: 1, f: x => num(x.devs)}], d.services), {flush: true, style: 'flex:1 1 400px'})}
</div>
${card('Flows: device, service, destination', 'Band thickness is the amount of data. Hover a band for figures', sankeyChart(d.sankey, col, colByName), {style: 'flex:none'})}
<div class="row">
${card(local ? 'Top destinations inside your home' : 'Top destination owners', local ? '' : 'The company whose network received it', tbl([{h: 'Destination', f: x => `<a style="color:var(--text)" href="${add({to: x.who})}">${e(x.who)}</a>${x.country ? `<div class="muted small">${e(x.country)}</div>` : ''}`}, {h: 'Data', f: x => barc(x.b, mx(d.dests), bytes(x.b))}, {h: 'Connections', r: 1, f: x => num(x.n)}, {h: 'Devices', r: 1, f: x => num(x.devs)}], d.dests), {flush: true, style: 'flex:2 1 440px'})}
${local ? '' : card('Top countries', 'Where your data went', tbl([{h: 'Country', f: x => `<a style="color:var(--text)" href="${add({cc: x.cc})}">${e(x.name)}</a>`}, {h: 'Data', f: x => barc(x.b, mx(d.countries), bytes(x.b))}, {h: 'Devices', r: 1, f: x => num(x.devs)}], d.countries), {flush: true, style: 'flex:1 1 320px'})}
${card('By network and protocol', '', `<div class="lbl">Networks</div><div>${d.nets.map(x => `<div class="kv"><span><a style="color:var(--text)" href="${add({net: x.net})}">${e(x.net)}</a> <span class="muted small">${num(x.devs)} devices</span></span><span>${bytes(x.b)}</span></div>`).join('') || '<div class="empty">None.</div>'}</div>
<div class="lbl">Protocols</div><div class="segbar" role="img" aria-label="Share of data by protocol">${d.protos.filter(x => x.b).map((x, i) => `<i style="flex:${Math.max(.5, 100 * x.b / psum)} 1 0;background:${SERIES[i % 3]}"${tipAttr([bytes(x.b) + `  (${Math.round(100 * x.b / psum)}%)`, x.proto, num(x.n) + ' connections'])}></i>`).join('')}</div>
<div>${d.protos.map((x, i) => `<div class="kv"><span><i class="sw" style="background:${SERIES[i % 3]}"></i>${e(x.proto)}</span><span>${bytes(x.b)} <span class="muted">· ${Math.round(100 * (x.b || 0) / psum)}%</span></span></div>`).join('')}</div>`, {style: 'flex:1 1 300px'})}
</div>
${card('Top conversations', 'One device talking to one destination', tbl([{h: 'Device', f: x => devl(x.mac, x.name || x.mac)}, {h: 'Talking to', c: 'clip', f: x => `<a style="color:var(--text)" href="${add({to: x.who})}">${e(x.who)}</a><div class="muted small">${e([x.domain, x.country].filter(Boolean).join(' · '))}</div>`}, {h: 'Using', f: x => e(x.svcs)}, {h: 'Data', f: x => barc(x.b, mx(d.conv), bytes(x.b))}, {h: 'Sent', r: 1, f: x => bytes(x.up)}, {h: 'Received', r: 1, f: x => bytes(x.down)}, {h: 'Connections', r: 1, f: x => num(x.n)}, {h: 'Last', f: x => `<span class="muted nowrap">${ago(x.last)}</span>`}], d.conv), {flush: true, style: 'flex:none'})}
<h2 class="verdict" style="font-size:20px;margin-top:8px">Whole-home checks</h2>
<div class="muted small" style="margin-top:-12px">These ignore the filters above and always cover every device.</div>
<div class="row">
${card('Between your networks', 'Data crossing from one network to another', matrixTable(d.matrix), {style: 'flex:1 1 420px'})}
${card('Devices doing their own DNS lookups', 'Bypassing your DNS filter', `<div class="muted small">These devices asked an outside DNS server directly, so your filter did not see or block those lookups.</div>${tbl([{h: 'Device', f: x => devl(x.mac, x.name || x.mac) + `<div class="muted small">${e(x.net)}</div>`}, {h: 'Asked', f: x => e(x.who) + `<div class="muted small mono">${e(x.ips)}</div>`}, {h: 'How', f: x => e(x.how)}, {h: 'Times', r: 1, f: x => num(x.n)}, {h: 'Last', f: x => `<span class="muted nowrap">${ago(x.last)}</span>`}], d.dnsbypass, 'None. Every device used your filter.')}`, {style: 'flex:1 1 460px'})}
</div>
<div class="row">
${card('Remote-control sessions', 'SSH, Telnet, Remote Desktop and screen sharing', tbl([{h: 'From', f: x => x.dir === 'incoming' ? ipl(x.src_ip) : devl(x.mac, x.src)}, {h: 'To', f: x => e(x.dst) + `<div class="muted small">${e(x.what)} · port ${x.dst_port}</div>`}, {h: 'Direction', f: x => ({outgoing: 'Out to the internet', incoming: '<span class="amber b">In from the internet</span>', local: 'Inside your home'})[x.dir] || e(x.dir)}, {h: 'Times', r: 1, f: x => num(x.n)}, {h: 'Data', r: 1, f: x => bytes(x.b)}, {h: 'Result', f: x => x.action === 'blocked' ? '<span class="pill ok">Blocked</span>' : '<span class="muted">Allowed</span>'}, {h: 'Last', f: x => `<span class="muted nowrap">${ago(x.last)}</span>`}], d.remote, 'No remote-control sessions in this period.'), {flush: true, style: 'flex:1 1 520px'})}
${card('Connections UniFi rated risky', 'Medium or high risk', tbl([{h: 'When', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'From', f: x => x.dir === 'incoming' ? e(x.src) : devl(x.mac, x.src)}, {h: 'To', c: 'clip', f: x => e(x.dst) + `<div class="muted small">${e(x.port)}</div>`}, {h: 'Risk', f: x => `<span class="pill ${x.risk === 'high' ? 'attack' : 'anomaly'}">${e(x.risk)}</span>`}, {h: 'Result', f: x => x.action === 'blocked' ? 'Blocked' : 'Allowed'}], d.risky, 'Nothing rated medium or high.'), {flush: true, style: 'flex:1 1 440px'})}
</div>`;
};
V.netflow = async r => {
  const d = await api('netflow', r.q), q = r.q, C = d.collector || {}, add = o => href('netflow', Object.assign({}, q, o));
  const health = `<div class="kv"><span class="muted">Listening</span><span>${C.listening ? 'UDP port ' + C.port : '<span class="red b">Not listening</span>'}</span></div>
<div class="kv"><span class="muted">Last packet from the gateway</span><span>${C.last ? ago(C.last) : '<span class="amber b">none yet</span>'}</span></div>
<div class="kv"><span class="muted">Records decoded since the portal started</span><span>${num(C.records)} <span class="muted">· ${C.rate} per second</span></span></div>
<div class="kv"><span class="muted">Stored in Elasticsearch</span><span>${num(C.stored)}${C.waiting ? ` <span class="muted">· ${num(C.waiting)} waiting</span>` : ''}</span></div>
<div class="kv"><span class="muted">Lost</span><span class="${C.dropped ? 'amber b' : ''}">${num(C.dropped)}${C.undecoded ? ` <span class="muted">· ${num(C.undecoded)} held until the gateway re-sends its format</span>` : ''}</span></div>
${C.error ? `<div class="kv"><span class="muted">Last problem</span><span class="red">${e(C.error)}</span></div>` : ''}`;
  if (d.setup) return `<h1 class="verdict" style="font-size:26px">NetFlow</h1>${card('Not set up yet', '', `<div>Add an Elasticsearch connection on the <a href="#/connections">Connections</a> page, then point your gateway's NetFlow export at this portal.</div><div>${health}</div>`, {style: 'flex:none'})}`;
  if (d.error) return `<h1 class="verdict" style="font-size:26px">NetFlow</h1>${card('Cannot read from Elasticsearch', '', `<div class="red b">${e(d.error)}</div><div>${health}</div>`, {style: 'flex:none'})}`;
  const T = d.total, S = d.store || {}, mx = (a, f) => Math.max(1, ...a.map(f || (x => x.b)));
  const cols = {up: SERIES[1], down: SERIES[0], local: SERIES[2]};
  const labels = {device: 'Device', peer: 'Talking to', svc: 'Service', dir: 'Direction', net: 'Network', ip: 'Address'}, on = Object.keys(q).filter(k => labels[k]);
  const dirName = {up: 'Sent to the internet', down: 'Received from the internet', local: 'Inside your home', other: 'Other'};
  const dur = ms => ms >= 3600000 ? (ms / 3600000).toFixed(1) + ' h' : ms >= 60000 ? Math.round(ms / 60000) + ' min' : Math.round(ms / 1000) + ' s';
  const FLAG = {S: 'Asked to connect, no answer seen', SA: 'Answered a connection', A: 'Mid-conversation', none: 'No flags'}, flagName = f => FLAG[f] || (f.includes('R') ? 'Refused or reset' : f.includes('F') ? 'Complete conversation' : f.includes('S') ? 'Connection opened, still running' : 'Mid-conversation');
  const fl = {}; d.flags.forEach(x => { const k = flagName(x.name); fl[k] = fl[k] || {name: k, n: 0, b: 0}; fl[k].n += x.n; fl[k].b += x.b; }); const flags = Object.values(fl).sort((a, b) => b.n - a.n);
  const dl = name => `<a style="color:var(--text)" href="${add({device: name})}">${e(name)}</a>`;
  return `<h1 class="verdict" style="font-size:26px">NetFlow: packet-level detail from the gateway</h1>
${on.length ? `<div class="chips"><span class="muted">Showing only:</span>${on.map(k => { const rest = Object.assign({}, q); delete rest[k]; return `<a class="chip on" href="${href('netflow', rest)}" title="Remove this filter">${labels[k]}: ${e(k === 'dir' ? dirName[q[k]] : q[k])} ✕</a>`; }).join('')}<a class="chip" href="#/netflow">Clear all</a></div>` : '<div class="muted small">Every connection the gateway carries for your home networks, with packet counts and connection flags. Click a device or service to narrow the page to it.</div>'}
<div class="card" style="flex:none"><div class="bd"><div class="stats">${stat(bytes(T.b), 'carried')}${stat(num(T.p), 'packets')}${stat(num(T.n), 'flow records')}${stat(num(T.devs), 'devices')}${stat(num(T.peers), 'other addresses')}${stat(T.p ? num(Math.round(T.b / T.p)) + ' <small>bytes</small>' : '—', 'average packet')}</div></div></div>
<div class="row">
${card('Data over time', 'Exact, from packet counts', stackChart(d.bytes_series, cols), {style: 'flex:1 1 520px'})}
${card('Packets over time', '', stackChart(d.packet_series, cols, 'packets'), {style: 'flex:1 1 520px'})}
</div>
<div class="row">
${card('Unanswered connection attempts', 'The pattern a scan or a broken device leaves', `<div class="muted small">A device asked to connect and no reply was recorded in that flow. A few are normal (a server that is off). Many different addresses or ports from one device is what scanning looks like.</div>${tbl([{h: 'Device', f: x => dl(x.device)}, {h: 'Attempts', f: x => barc(x.n, mx(d.unanswered, y => y.n))}, {h: 'Different addresses', r: 1, f: x => x.dsts > 20 ? `<span class="amber b">${num(x.dsts)}</span>` : num(x.dsts)}, {h: 'Different ports', r: 1, f: x => x.ports > 20 ? `<span class="amber b">${num(x.ports)}</span>` : num(x.ports)}, {h: 'Mostly to', c: 'clip', f: x => e(x.top.join(', '))}, {h: 'Last', f: x => `<span class="muted nowrap">${ago(x.last)}</span>`}], d.unanswered, 'None in this period.')}`, {style: 'flex:2 1 560px'})}
${card('How connections went', 'TCP only', tbl([{h: 'Outcome', f: x => e(x.name)}, {h: 'Flows', f: x => barc(x.n, mx(flags, y => y.n))}, {h: 'Data', r: 1, f: x => bytes(x.b)}], flags, 'No TCP flows yet.'), {flush: true, style: 'flex:1 1 360px'})}
</div>
<div class="row">
${card('Top talkers', 'By data, with packets', tbl([{h: 'Device', f: x => dl(x.name) + `<div class="muted small">${e(x.net)}</div>`}, {h: 'Data', f: x => barc(x.b, mx(d.talkers), bytes(x.b))}, {h: 'Packets', r: 1, f: x => num(x.p)}, {h: 'Flows', r: 1, f: x => num(x.n)}, {h: 'Addresses', r: 1, f: x => num(x.peers)}], d.talkers), {flush: true, style: 'flex:1 1 460px'})}
${card('Top services', 'With average packet size', tbl([{h: 'Service', f: x => `<a style="color:var(--text)" href="${add({svc: x.name})}">${e(x.name)}</a>`}, {h: 'Data', f: x => barc(x.b, mx(d.services), bytes(x.b))}, {h: 'Packets', r: 1, f: x => num(x.p)}, {h: 'Avg packet', r: 1, f: x => x.p ? num(Math.round(x.b / x.p)) + ' B' : ''}, {h: 'Devices', r: 1, f: x => num(x.devs)}], d.services), {flush: true, style: 'flex:1 1 460px'})}
</div>
${card('Top conversations', 'Device, the other end and the service', tbl([{h: 'Device', f: x => dl(x.device)}, {h: 'Talking to', c: 'clip', f: x => `<a style="color:var(--text)" href="${add({peer: x.peer})}">${e(x.peer)}</a>`}, {h: 'Service', f: x => e(x.service)}, {h: 'Data', f: x => barc(x.b, mx(d.conv), bytes(x.b))}, {h: 'Packets', r: 1, f: x => num(x.p)}, {h: 'Flows', r: 1, f: x => num(x.n)}, {h: 'Longest flow', r: 1, f: x => dur(x.dur)}, {h: 'Last', f: x => `<span class="muted nowrap">${ago(x.last)}</span>`}], d.conv), {flush: true, style: 'flex:none'})}
<div class="row">
${card('Longest-running connections', 'Persistent links: tunnels, streams, always-on devices', tbl([{h: 'Device', f: x => dl(x.device)}, {h: 'Talking to', c: 'clip', f: x => e(x.peer)}, {h: 'Service', f: x => e(x.service)}, {h: 'Lasted', r: 1, f: x => dur(x.duration_ms)}, {h: 'Data', r: 1, f: x => bytes(x.bytes)}, {h: 'Ended', f: x => `<span class="muted">${e(x.end_reason)}</span>`}], d.longest), {flush: true, style: 'flex:2 1 520px'})}
${card('By network', '', `<div>${d.nets.map(x => `<div class="kv"><span><a style="color:var(--text)" href="${add({net: x.name})}">${e(x.name)}</a></span><span>${bytes(x.b)} <span class="muted">· ${num(x.p)} packets</span></span></div>`).join('') || '<div class="empty">None.</div>'}</div><div class="lbl">Why flows ended</div><div>${d.reasons.map(x => `<div class="kv"><span>${e(x.name)}</span><span class="muted">${num(x.n)}</span></div>`).join('')}</div>`, {style: 'flex:1 1 300px'})}
${card('Collector health', C.error ? '<span class="pill attack">Problem</span>' : C.last && Date.now() / 1000 - C.last < 600 ? '<span class="pill ok">Receiving</span>' : '<span class="pill anomaly">Quiet</span>', `<div>${health}<div class="kv"><span class="muted">Held in Elasticsearch</span><span>${S.docs !== undefined ? num(S.docs) + ' records · ' + bytes(S.bytes) : 'unknown'}</span></div><div class="kv"><span class="muted">Kept for</span><span>30 days</span></div></div>`, {style: 'flex:1 1 320px'})}
</div>
${card('Flow records', 'Newest first, up to 150', tbl([{h: 'Ended', f: x => `<span class="muted nowrap">${when(x.ts)}</span>`}, {h: 'Device', f: x => dl(x.device)}, {h: 'Direction', f: x => `<a style="color:var(--text)" href="${add({dir: x.dir})}">${e(dirName[x.dir] || x.dir)}</a>`}, {h: 'Other end', c: 'clip', f: x => e(x.peer) + `<div class="muted small mono">${e(x.peer_ip)}</div>`}, {h: 'Service', f: x => e(x.service) + `<div class="muted small">${e(x.proto)} ${x.src_port} → ${x.dst_port}</div>`}, {h: 'Data', r: 1, f: x => bytes(x.bytes)}, {h: 'Packets', r: 1, f: x => num(x.packets)}, {h: 'Lasted', r: 1, f: x => dur(x.duration_ms)}, {h: 'Flags', f: x => x.flags ? `<span class="mono muted" title="${e(flagName(x.flags))}">${e(x.flags)}</span>` : ''}], d.recent), {flush: true, style: 'flex:none'})}`;
};
V.connections = async () => {
  const d = await api('connections'), U = d.unifi, C = d.crowdsec;
  const fresh = (t, max) => !t ? '<span class="pill attack">No data yet</span>' : d.now - t > max ? `<span class="pill anomaly">Stale · ${ago(t)}</span>` : `<span class="pill ok">Working · ${ago(t)}</span>`;
  const uok = U.last_ok && (!U.error || U.last_ok > U.error_ts), cok = C.last_ok && !C.error;
  const btns = (t, sv) => `<div class="chips"><button class="btn" name="go" value="${t}">Test</button><button class="btn pri" name="go" value="${sv}">Test and save</button><span class="cmsg muted" role="status"></span></div>`;
  const inp = (n, ph, o) => `<label style="display:flex;flex-direction:column;gap:4px;min-width:0;flex:${(o && o.w) || '1 1 180px'}"><span class="muted small">${e((o && o.l) || ph)}</span><input type="${(o && o.pw) ? 'password' : 'text'}" name="${n}" value="${e((o && o.v) || '')}" placeholder="${e((o && o.ph) || '')}" autocomplete="${(o && o.pw) ? 'new-password' : 'off'}"></label>`;
  const MASK = '••••••••', saved = t => t ? `${MASK}${t === true ? '' : t}  (saved; type to replace)` : 'not set';
  return `<h1 class="verdict" style="font-size:26px">Connections: where the portal gets its data</h1>
<div class="note">Each connection is tested before it is saved, so a typo cannot cut the portal off. Leave a field blank to keep what is saved now. Passwords and keys are stored on the portal's own machine and are never shown again.</div>
${(() => { const S = d.signin, V = d.visit, sso = S.mode === 'sso';
  return card('Signing in to the portal', sso ? `<span class="pill ok">Password, plus ${e(S.name || 'single sign-on')}</span>` : '<span class="pill info">Password only</span>', `
<div><div class="kv"><span class="muted">Portal password</span><span>${sso && S.bypass !== false ? 'Skipped for single sign-on visitors; required for everyone else, including on your home network address' : sso ? 'Required for everyone, after single sign-on' : 'Required for everyone'}</span></div>
<div class="kv"><span class="muted">Single sign-on</span><span>${sso ? `${e(S.name)} · trusts <span class="mono">${e(S.header)}</span> from ${S.proxies.map(e).join(', ')} · ${S.users.length ? 'only ' + S.users.map(e).join(', ') : 'any signed-in account'}` : 'Off'}</span></div>
<div class="kv"><span class="muted">This visit</span><span>${V.user ? 'Signed in through single sign-on as ' + e(V.user) : V.via_proxy ? 'Came through the reverse proxy with the portal password' : 'Came straight from ' + e(V.peer) + ' with the portal password'}${V.headers.length && !V.user ? ' · the proxy sent ' + V.headers.map(x => e(x[0])).join(', ') : ''}</span></div></div>
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="lbl">Set up, change or remove single sign-on</div>
<div class="chips"><label style="display:flex;flex-direction:column;gap:4px;min-width:0;max-width:100%;flex:0 1 320px"><span class="muted small">Sign-in method</span><select name="provider" class="btn" aria-label="Sign-in method" data-hdr='${e(JSON.stringify(Object.fromEntries(S.options.map(o => [o[0], o[2]]))))}'><option value="password" ${sso ? '' : 'selected'}>Password only</option>${S.options.map(o => `<option value="${e(o[0])}" ${sso && S.provider === o[0] ? 'selected' : ''}>${e(o[1])}</option>`).join('')}</select></label></div>
<div class="muted small">oauth2-proxy covers Keycloak, Pocket ID, Google, GitHub and similar. "Password only" removes single sign-on.</div>
<div class="chips">${inp('proxies', 'Reverse proxy address the portal trusts', {w: '1 1 240px', v: S.proxies.join(', '), ph: '192.168.1.20'})}${inp('header', 'Header that carries the signed-in name', {w: '1 1 260px', v: S.header, ph: 'set by the provider you pick'})}</div>
<div class="chips">${inp('users', 'Only allow these account names (optional, comma separated)', {w: '1 1 420px', v: S.users.join(', '), ph: 'anyone your provider lets in'})}</div>
<label class="chip" style="align-self:flex-start;border-radius:10px;padding:10px 14px"><input type="checkbox" name="bypass" ${S.bypass !== false && sso ? 'checked' : ''} style="width:18px;height:18px"> Skip the portal password for visitors who signed in through single sign-on</label>
${btns('signin-test', 'signin-save')}
<div class="muted small">How it works: your reverse proxy sends visitors to the provider, and after they sign in it tells the portal who they are in a header. The portal only believes that header when it arrives from the proxy address you list here. The portal cannot change your proxy or your provider, so setting up or removing the sign-in page itself is done there. Blank fields keep what is saved; the header defaults to the provider's standard one.</div>
</form>
<details><summary class="lbl" style="cursor:pointer">Proxy setup text for authentik on Nginx Proxy Manager</summary><div style="display:flex;flex-direction:column;gap:10px;margin-top:10px">
<div class="muted small">Paste this into the proxy host's Advanced tab, replacing AUTHENTIK-INTERNAL-ADDRESS and AUTHENTIK-PUBLIC-NAME. It is the setup this portal uses, for authentik's "forward auth (domain level)" mode. To remove single sign-on, clear the Advanced tab again and choose "Password only" above. Authelia, Tinyauth, oauth2-proxy and Cloudflare Access each publish their own proxy text; use theirs and pick the matching provider above.</div>
<div><button class="btn" data-copytext="${e(NPM_AUTHENTIK)}">Copy</button></div>
<pre class="mono" style="margin:0;background:#0B0F13;border:1px solid var(--line2);border-radius:8px;padding:12px;overflow:auto;max-height:260px">${e(NPM_AUTHENTIK)}</pre></div></details>
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="lbl">Change the portal password</div>
<div class="chips">${inp('password', 'New password, at least 10 characters', {pw: 1})}${inp('repeat', 'Same again', {pw: 1})}<button class="btn pri" name="go" value="set-password">Change password</button><span class="cmsg muted" role="status"></span></div>
</form>`, {style: 'flex:none'}); })()}
<div class="row">
${card('UniFi gateway', uok ? `<span class="pill ok">Connected · ${ago(U.last_ok)}</span>` : `<span class="pill attack">Not connected</span>`, `
<div><div class="kv"><span class="muted">Address</span><span class="mono">${e(U.url)}</span></div>
<div class="kv"><span class="muted">Signing in with</span><span>${U.mode === 'account' ? 'Local account ' + e(U.username) : 'API key ending ' + e(U.key_tail)}</span></div>
${U.error && !uok ? `<div class="kv"><span class="muted">Last error</span><span class="red">${e(U.error)}</span></div>` : ''}</div>
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="lbl">Change the connection</div>
<div class="chips">${inp('url', 'Gateway address', {w: '1 1 320px', v: U.url, ph: 'https://192.168.1.1'})}</div>
<div class="chips"><label class="chip"><input type="radio" name="mode" value="account" ${U.mode === 'account' ? 'checked' : ''}> Local admin account</label><label class="chip"><input type="radio" name="mode" value="key" ${U.mode !== 'account' ? 'checked' : ''}> API key</label></div>
<div class="chips">${inp('username', 'Local account name', {v: U.username, ph: 'not set'})}${inp('password', 'Local account password', {pw: 1, ph: U.mode === 'account' && U.has_password ? saved(true) : 'not set'})}</div>
<div class="chips">${inp('key', 'API key', {pw: 1, w: '1 1 320px', ph: U.mode !== 'account' && U.key_tail ? saved(U.key_tail) : 'not set'})}</div>
${btns('conn-test', 'conn-save')}
<div class="muted small">Fill in only the fields for the method you chose. The account must be a local-only UniFi admin with full Network rights and no two-step sign-in.</div>
</form>`, {style: 'flex:1 1 460px'})}
${card('CrowdSec', cok ? `<span class="pill ok">Connected · ${ago(C.last_ok)}</span>` : `<span class="pill attack">Not connected</span>`, `
<div><div class="kv"><span class="muted">Address</span><span class="mono">${e(C.url || 'not set')}</span></div><div class="kv"><span class="muted">Signed in as</span><span>${e(C.machine || 'not set')}</span></div>
<div class="kv"><span class="muted">Blocklist counts from</span><span class="mono">${e(C.metrics || 'not set')}</span></div>${C.error ? `<div class="kv"><span class="muted">Last error</span><span class="red">${e(C.error)}</span></div>` : ''}</div>
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="lbl">Change the connection</div>
<div class="chips">${inp('url', 'CrowdSec address', {w: '1 1 320px', v: C.url, ph: 'http://192.168.1.20:8080'})}</div>
<div class="chips">${inp('machine', 'Machine name', {v: C.machine, ph: 'homeportal'})}${inp('password', 'Machine password', {pw: 1, ph: C.has_password ? saved(true) : 'not set'})}</div>
<div class="chips">${inp('metrics', 'Metrics address (optional)', {w: '1 1 320px', v: C.metrics, ph: 'http://192.168.1.20:6060/metrics'})}</div>
${btns('cs-test', 'cs-save')}
<div class="muted small">Create the machine on the CrowdSec host with: <span class="mono">cscli machines add homeportal --password 'choose-one'</span>. The metrics address is only used to count community-blocklist entries.</div>
</form>`, {style: 'flex:1 1 460px'})}
</div>
${(() => { const E = d.elastic, N = d.netflow, ok = N.last_stored && !N.error;
  return card('NetFlow and Elasticsearch', !E.url ? '<span class="pill info">Not set up</span>' : ok ? `<span class="pill ok">Storing · ${ago(N.last_stored)}</span>` : N.error ? '<span class="pill attack">Problem</span>' : '<span class="pill anomaly">Waiting for records</span>', `
<div><div class="kv"><span class="muted">Collector</span><span>${N.listening ? `Listening on <span class="mono">${e(d.portal_ip)}</span> UDP port ${N.port}` : 'Not listening'}</span></div>
<div class="kv"><span class="muted">Last packet from a gateway</span><span>${N.last ? ago(N.last) : 'none yet'}${N.exporters.length ? ' · from ' + N.exporters.map(x => e(x.ip)).join(', ') : ''}</span></div>
<div class="kv"><span class="muted">Records decoded / stored / lost</span><span>${num(N.records)} / ${num(N.stored)} / ${num(N.dropped)}</span></div>
${N.error ? `<div class="kv"><span class="muted">Last problem</span><span class="red">${e(N.error)}</span></div>` : ''}</div>
<form class="cform" style="display:flex;flex-direction:column;gap:12px">
<div class="lbl">Elasticsearch connection</div>
<div class="chips">${inp('url', 'Elasticsearch address', {w: '1 1 320px', v: E.url, ph: 'https://192.168.1.30:9200'})}</div>
<div class="chips">${inp('username', 'User name', {v: E.username, ph: 'hc_portal'})}${inp('password', 'Password', {pw: 1, ph: E.has_password ? saved(true) : 'not set'})}</div>
<div class="chips">${inp('exporters', 'Only accept NetFlow from these addresses (comma separated; blank accepts any)', {w: '1 1 420px', v: E.exporters, ph: '192.168.1.1'})}</div>
${btns('es-test', 'es-save')}
<div class="muted small">To send NetFlow here from a UniFi gateway: in UniFi Network settings, turn on NetFlow (IPFIX, version 10), choose the networks to export, and set the server to <span class="mono">${e(d.portal_ip)}</span> port ${N.port}. The portal needs an Elasticsearch user that can write and read the <span class="mono">hc-flows</span> data stream.</div>
</form>`, {style: 'flex:none'}); })()}
${card('DNS filters', 'AdGuard Home and Pi-hole', `
${tbl([{h: 'Name', f: x => `<span class="b">${e(x.name)}</span><div class="muted small">${x.type === 'pihole' ? 'Pi-hole' : 'AdGuard Home'} · <span class="mono">${e(x.url)}</span>${x.username ? ' · as ' + e(x.username) : ''}</div>`}, {h: 'Status', f: x => x.err ? `<span class="pill attack">Failing</span><div class="red small">${e(x.err)}</div>` : fresh(x.ok, 300)}, {h: 'Lookups read', r: 1, f: x => num(x.n)}, {h: '', f: x => `<button class="btn sm" data-act='${e(JSON.stringify({action: 'dns-remove', id: x.id}))}' data-confirm="Stop reading lookups from ${e(x.name)}? What was already collected stays until you delete it under Data feeds.">Remove</button>`}], d.dns, 'No filters are connected here. Yours currently arrive through the log shippers listed under Data feeds.')}
<form class="cform" data-reset="1" style="display:flex;flex-direction:column;gap:12px">
<div class="lbl">Add a filter</div>
<div class="chips"><select name="type" class="btn" aria-label="Filter type"><option value="adguard">AdGuard Home</option><option value="pihole">Pi-hole (version 6 or later)</option></select>${inp('name', 'Short name', {w: '1 1 160px', ph: 'adguard1'})}${inp('url', 'Address', {w: '2 1 260px', ph: 'http://192.168.1.53'})}</div>
<div class="chips">${inp('username', 'User name (AdGuard Home only)')}${inp('password', 'Password', {pw: 1})}</div>
${btns('dns-test', 'dns-save')}
<div class="muted small">The portal reads the filter's query log over its web address every 30 seconds. For Pi-hole, use the web password or an app password and leave the user name blank. If a filter already sends its log through a shipper, remove that shipper first or its lookups are counted twice.</div>
</form>`, {style: 'flex:none'})}
${card('Reverse proxy and other log files', 'Nginx Proxy Manager', `
<div class="muted">Nginx Proxy Manager has no way to hand its access logs over the network, so a small helper (a "shipper") runs on the proxy machine and sends new log lines here. One command installs it.</div>
${tbl([{h: 'Machine', f: x => `<span class="b">${e(x.host)}</span><div class="muted small">${e(x.kind)}</div>`}, {h: 'Status', f: x => fresh(x.last, x.kind.startsWith('DNS') ? 86400 : 900)}, {h: 'Lines since the portal last restarted', r: 1, f: x => num(x.lines)}], d.shippers, 'No shipper has delivered anything since the portal last restarted.')}
<div class="lbl">Connect a Nginx Proxy Manager machine</div>
<div class="muted small">Run this as root on the machine (or container) that holds the proxy's log files. If the logs are not in <span class="mono">/data/logs</span>, which is common with Docker, put <span class="mono">LOG_DIR=/your/path/data/logs</span> in front of <span class="mono">sh</span>.</div>
<div class="chips"><code class="mono" style="flex:1 1 400px;background:#0B0F13;border:1px solid var(--line2);border-radius:8px;padding:10px 12px;overflow-wrap:anywhere">${e(d.install.npm)}</code><button class="btn" data-copytext="${e(d.install.npm)}">Copy</button></div>
<div class="lbl">Connect an AdGuard Home machine by its log file instead</div>
<div class="muted small">Only needed if you would rather not give the portal an AdGuard login under DNS filters above. Use one method per AdGuard, not both.</div>
<div class="chips"><code class="mono" style="flex:1 1 400px;background:#0B0F13;border:1px solid var(--line2);border-radius:8px;padding:10px 12px;overflow-wrap:anywhere">${e(d.install.adguard)}</code><button class="btn" data-copytext="${e(d.install.adguard)}">Copy</button></div>
<div class="lbl">Disconnect a machine</div>
<div class="muted small">Run this as root on that machine to remove the shipper. Its row above disappears the next time the portal restarts; what it already sent stays until you delete it under Data feeds.</div>
<div class="chips"><code class="mono" style="flex:1 1 400px;background:#0B0F13;border:1px solid var(--line2);border-radius:8px;padding:10px 12px;overflow-wrap:anywhere">${e(UNSHIP)}</code><button class="btn" data-copytext="${e(UNSHIP)}">Copy</button></div>
<div class="muted small">These commands contain the portal's feed password, so treat them like a password. They only work from inside your network (${e(d.install.base)}), and the machine needs Python 3 and systemd.</div>`, {style: 'flex:none'})}
${card('Data feeds', 'When each one last delivered', tbl([{h: 'Feed', f: x => `<span class="b">${e(x[0])}</span><div class="muted small">${e(x[1])}</div>`}, {h: 'Status', f: x => fresh(x[2], x.length > 3 ? 86400 : 900)}, {h: '', f: x => x.length > 3 ? `<button class="btn sm" data-act='${e(JSON.stringify({action: 'dns-purge', inst: x[3]}))}' data-confirm="Delete every stored lookup from ${e(x[3])}? This cannot be undone. If it is still connected, new lookups will keep arriving.">Delete its lookups</button>` : ''}], d.sources), {flush: true, style: 'flex:none'})}`;
};
V.page = async r => (V[r.arg] || V.home)({q: {}, arg: ''});

// ---------- shell ----------
function chrome() {
  const r = route(), cur = {device: 'devices', ip: 'proxy', item: 'home', setup: 'settings'}[r.page] || r.page;
  $('#nav').innerHTML = PAGES.map(([k, l]) => `<a href="#/${k}" class="${k === cur ? 'on' : ''}">${l}</a>`).join('');
  $('#range').innerHTML = Object.entries(RANGES).map(([k, l]) => `<button data-range="${k}" class="${k === range ? 'on' : ''}">${l}</button>`).join('');
}
async function render(quiet) {
  if (loading) return; loading = true; const r = route(), fn = V[r.page] || V.home;
  try {
    if (!WORLD) WORLD = await (await fetch('/static/world.json')).json();
    const html = await fn(r); const cur = route();
    if (cur.page === r.page && cur.arg === r.arg && (forceRender || !(quiet && (busy() || reading())))) { forceRender = false;
      const y = window.scrollY, tops = quiet ? [...document.querySelectorAll('.tw')].map(x => x.scrollTop) : [];
      $('#main').innerHTML = html;
      if (quiet) { document.querySelectorAll('.tw').forEach((x, i) => { if (tops[i]) x.scrollTop = tops[i]; }); window.scrollTo(0, y); } else window.scrollTo(0, 0);
    }
    lastOk = Date.now(); liveLabel();
  } catch (x) {
    if (x.message !== 'login') { $('#live .dot').className = 'dot off'; $('#livetxt').textContent = 'Not updating'; if (!quiet) $('#main').innerHTML = `<div class="empty">Could not load this page: ${e(x.message)}</div>`; }
  } finally { loading = false; }
}
// Scrolled down inside a list: hold the page still until the reader returns to the top of it.
function reading() { return [...document.querySelectorAll('.tw')].some(x => x.scrollTop > 8) || [...document.querySelectorAll('.cform input:not([type=radio]):not([type=checkbox])')].some(x => x.value !== x.defaultValue) || [...document.querySelectorAll('.cform input[type=checkbox], .cform input[type=radio]')].some(x => x.checked !== x.defaultChecked) || [...document.querySelectorAll('.cform select')].some(x => [...x.options].some(o => o.selected !== o.defaultSelected)) || [...document.querySelectorAll('.cmsg')].some(x => x.textContent) || !!document.querySelector('details[open]'); }
function liveLabel() { const p = reading(); $('#live .dot').className = p ? 'dot off' : 'dot'; $('#livetxt').textContent = p ? 'Paused while you read' : 'Live'; }
document.addEventListener('scroll', ev => { if (ev.target.classList && ev.target.classList.contains('tw')) liveLabel(); }, true);
function busy() { const a = document.activeElement; return (a && ['INPUT', 'SELECT', 'TEXTAREA'].includes(a.tagName)) || String(window.getSelection()).length > 0; }
function start() {
  chrome(); render(false); clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden && !reading()) render(true); }, route().page === 'home' ? 5000 : 10000);
}
function showSetup() {
  clearInterval(timer); document.querySelector('header').style.display = 'none';
  $('#main').innerHTML = `<form id="setupform" style="max-width:420px;margin:12vh auto;padding:0 20px;display:flex;flex-direction:column;gap:14px"><h1 class="verdict" style="font-size:28px">Welcome to Home Command</h1><div class="muted">This is a new install. Start by choosing the password that protects this portal.</div><label class="muted" for="npw">Password, at least 10 characters</label><input id="npw" type="password" autocomplete="new-password" autofocus><label class="muted" for="npw2">Same again</label><input id="npw2" type="password" autocomplete="new-password"><button class="btn pri" style="justify-content:center">Create password and continue</button><div id="lerr" class="red"></div></form>`;
}
function showLogin() {
  clearInterval(timer); document.querySelector('header').style.display = 'none';
  $('#main').innerHTML = `<form id="login"><h1 class="verdict" style="font-size:26px">Home Command</h1><label for="pw" class="muted">Password</label><input id="pw" type="password" autocomplete="current-password" autofocus><button class="btn pri" style="justify-content:center">Sign in</button><div id="lerr" class="red"></div></form>`;
}
window.addEventListener('hashchange', start);
document.addEventListener('submit', async ev => {
  ev.preventDefault(); const f = ev.target;
  try {
    if (f.id === 'login') { await post('/login', {password: $('#pw').value}); document.querySelector('header').style.display = ''; start(); }
    if (f.id === 'setupform') { await post('/setup', {password: $('#npw').value, repeat: $('#npw2').value}); document.querySelector('header').style.display = ''; STEP = 0; if (location.hash === '#/setup') start(); else location.hash = '#/setup'; }
    if (f.classList.contains('cform')) {
      const m = f.querySelector('.cmsg'), go = (ev.submitter && ev.submitter.value) || '', body = {action: go};
      for (const el of f.elements) if (el.name && el.name !== 'go' && (el.type !== 'radio' || el.checked)) body[el.name] = el.type === 'checkbox' ? el.checked : el.value;
      const grp = Object.keys(body).filter(k => k.startsWith('iot:')); if (grp.length) { body.iot_networks = grp.filter(k => body[k]).map(k => k.slice(4)); grp.forEach(k => delete body[k]); }
      m.className = 'cmsg muted'; m.textContent = /^settings-save$/.test(go) ? 'Saving…' : 'Testing…';
      try { const r = await post('/api/action', body); m.className = 'cmsg b'; m.textContent = r.msg; if (ev.submitter && ev.submitter.dataset.then) { location.hash = ev.submitter.dataset.then; return; } if (/-save$|^set-password$/.test(go)) { f.querySelectorAll('input[type=password]').forEach(x => { x.value = ''; }); f.querySelectorAll('input[type=text]').forEach(x => { x.defaultValue = x.value; }); setTimeout(() => { m.textContent = ''; forceRender = true; render(true); }, 6000); } }
      catch (x) { m.className = 'cmsg red b'; m.textContent = x.message; }
      return;
    }
    if (f.id === 'listform') { await post('/api/action', {action: 'gw-list-add', name: f.name.value, url: f.url.value}); f.reset(); document.activeElement && document.activeElement.blur(); forceRender = true; render(true); }
    if (f.id === 'banform') { const ip = f.ip.value.trim(); if (!confirm(`Ban ${ip} for ${f.hours.selectedOptions[0].text}?`)) return; await post('/api/action', {action: 'ban', ip, hours: Number(f.hours.value), reason: f.reason.value}); render(false); }
  } catch (x) { if (f.id === 'login' || f.id === 'setupform') $('#lerr').textContent = x.message; else alert(x.message); }
});
document.addEventListener('click', async ev => {
  const t = ev.target.closest('[data-act],[data-range],[data-name],[data-copy],[data-ban],[data-geo],[data-geopick],[data-cc],[data-copytext],#logout'); if (!t) { $('#results').style.display = 'none'; return; }
  try {
    if (t.dataset.cc) { t.checked ? GEO.add(t.dataset.cc) : GEO.delete(t.dataset.cc); return; }
    if (t.dataset.geopick) {
      if (t.dataset.geopick === 'none') GEO.clear();
      else [...document.querySelectorAll('[data-cc]')].slice(0, 10).forEach(x => GEO.add(x.dataset.cc));
      loading = false; forceRender = true; render(true); return;
    }
    if (t.dataset.geo) {
      const m = t.dataset.geo, list = [...GEO];
      const q = m === 'off' ? 'Turn off country blocking on the gateway?' : m === 'in' ? `Block inbound connections from ${list.length} countries at the gateway?` : `Block ALL traffic to and from ${list.length} countries at the gateway? Apps and smart devices that rely on servers there will stop working.`;
      if (!confirm(q)) return;
      t.disabled = true; await post('/api/action', {action: 'gw-geo', mode: m, countries: m === 'off' ? [] : list}); GEO = null; loading = false; forceRender = true; render(true); return;
    }
    if (t.dataset.ban) {
      const sel = t.parentElement.querySelector('[data-banfor]'), label = sel.selectedOptions[0].text.toLowerCase();
      if (!confirm(`Ban ${t.dataset.ban} ${label === 'permanently' ? 'permanently' : 'for ' + label}?`)) return;
      t.disabled = true; await post('/api/action', {action: 'ban', ip: t.dataset.ban, hours: Number(sel.value), reason: t.dataset.reason}); document.activeElement && document.activeElement.blur(); loading = false; render(true); return;
    }
    if (t.dataset.copytext) {
      try { await navigator.clipboard.writeText(t.dataset.copytext); } catch (x) { const a = document.createElement('textarea'); a.value = t.dataset.copytext; document.body.appendChild(a); a.select(); document.execCommand('copy'); a.remove(); }
      t.textContent = 'Copied'; setTimeout(() => { t.textContent = 'Copy'; }, 1500); return;
    }
    if (t.dataset.copy) {
      try { await navigator.clipboard.writeText(PROMPT); } catch (x) { const a = document.createElement('textarea'); a.value = PROMPT; document.body.appendChild(a); a.select(); document.execCommand('copy'); a.remove(); }
      t.textContent = 'Copied'; setTimeout(() => { t.textContent = 'Copy question'; }, 1500); return;
    }
    if (t.id === 'logout') { await post('/logout'); showLogin(); return; }
    if (t.dataset.range) { range = t.dataset.range; try { localStorage.setItem('hc_range', range); } catch (x) {} start(); return; }
    if (t.dataset.name) { const label = prompt('Name for this device:'); if (!label) return; await post('/api/action', {action: 'label-device', mac: t.dataset.name, label}); render(true); return; }
    if (t.dataset.confirm && !confirm(t.dataset.confirm)) return;
    const body = JSON.parse(t.dataset.act); t.disabled = true; await post('/api/action', body); document.activeElement && document.activeElement.blur(); loading = false;
    if (route().page === 'item' && ['dismiss', 'known'].includes(body.action)) { location.hash = '#/home'; return; }
    render(true);
  } catch (x) { alert(x.message); t.disabled = false; }
});
document.addEventListener('change', ev => { const t = ev.target; if (t.dataset && t.dataset.hdr) { const h = t.form.querySelector('[name=header]'); if (h) h.value = JSON.parse(t.dataset.hdr)[t.value] || ''; } });
const TIP = document.createElement('div'); TIP.id = 'tip'; TIP.setAttribute('role', 'tooltip'); document.body.appendChild(TIP);
function showTip(t, x, y) {
  const lines = t.dataset.tip.split('\n'); TIP.textContent = '';
  lines.forEach((l, i) => { const el = document.createElement('div'); el.textContent = l; if (i === 0) el.className = 'b'; TIP.appendChild(el); });
  TIP.style.display = 'block'; const w = TIP.offsetWidth, h = TIP.offsetHeight;
  TIP.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, x + 14)) + 'px'; TIP.style.top = Math.max(8, y - h - 12 < 8 ? y + 18 : y - h - 12) + 'px';
}
document.addEventListener('pointermove', ev => { const t = ev.target.closest && ev.target.closest('[data-tip]'); if (t) showTip(t, ev.clientX, ev.clientY); else TIP.style.display = 'none'; });
document.addEventListener('pointerdown', ev => { const t = ev.target.closest && ev.target.closest('[data-tip]'); if (t) showTip(t, ev.clientX, ev.clientY); else TIP.style.display = 'none'; });
window.addEventListener('scroll', () => { TIP.style.display = 'none'; }, true);
$('#search').addEventListener('keydown', async ev => {
  if (ev.key !== 'Enter') return; const d = await api('search', {q: ev.target.value}); const box = $('#results');
  box.innerHTML = d.results.map(x => `<a href="${e(x.href)}">${e(x.label)}</a>`).join('') || '<div class="empty">No matches.</div>'; box.style.display = 'block';
});
start();
