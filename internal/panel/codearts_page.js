'use strict';
(function () {
  const $ = (id) => document.getElementById(id);
  let oauthTimer = null;

  function apiKey() {
    let key = localStorage.getItem('wb2api.key') || '';
    if (!key) {
      key = window.prompt('请输入网关面板 API Key（与 /v1 的 api_key 相同）') || '';
      if (key) localStorage.setItem('wb2api.key', key);
    }
    return key;
  }

  async function api(path, options) {
    const key = apiKey();
    if (!key) throw new Error('缺少 API Key');
    const opts = options || {};
    opts.headers = Object.assign({}, opts.headers || {}, { Authorization: 'Bearer ' + key });
    if (opts.body && !opts.headers['Content-Type']) opts.headers['Content-Type'] = 'application/json';
    const resp = await fetch(path, opts);
    if (resp.status === 401) {
      localStorage.removeItem('wb2api.key');
      throw new Error('API Key 无效，请重新打开页面输入');
    }
    const text = await resp.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { error: text }; }
    if (!resp.ok) throw new Error(data.error || data.message || ('HTTP ' + resp.status));
    return data;
  }

  function msg(text, bad) {
    const el = $('msg');
    el.textContent = text || '';
    el.style.color = bad ? 'var(--bad)' : 'var(--muted)';
  }

  function showOAuth(url) {
    const box = $('oauthBox');
    box.style.display = 'block';
    box.innerHTML = '';
    const p = document.createElement('p');
    p.textContent = '请在浏览器打开以下链接完成华为云授权。授权完成后本页会自动检测。';
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener';
    a.textContent = url;
    box.appendChild(p);
    box.appendChild(a);
    const s = document.createElement('p');
    s.className = 'muted';
    s.textContent = '等待授权中…';
    box.appendChild(s);
  }

  function stopOAuthPoll() {
    if (oauthTimer) { clearInterval(oauthTimer); oauthTimer = null; }
  }

  async function pollOAuth(session) {
    stopOAuthPoll();
    oauthTimer = setInterval(async () => {
      try {
        const d = await api('/panel/api/codearts/oauth/poll?session=' + encodeURIComponent(session));
        if (d.status === 'done') {
          stopOAuthPoll();
          $('oauthBox').innerHTML = '<p>授权成功：' + (d.nickname || d.uid || '') + '</p>';
          await load();
        } else if (d.status === 'error') {
          stopOAuthPoll();
          $('oauthBox').innerHTML = '<p style="color:var(--bad)">授权失败：' + (d.message || '') + '</p>';
        }
      } catch (e) { /* keep polling; transient fetch errors are harmless */ }
    }, 2000);
  }

  async function load() {
    const d = await api('/panel/api/codearts');
    const c = d.config || {};
    $('enabled').checked = !!c.enabled;
    $('timeout').value = c.timeout_seconds || 30;
    $('stream_timeout').value = c.stream_timeout_seconds || 600;
    $('models_ttl').value = c.models_ttl_seconds || 300;
    $('max_concurrent').value = c.max_concurrent || 1;
    $('busy_wait').value = c.busy_wait_seconds || 0;
    $('benefit_auto_claim').checked = c.benefit_auto_claim !== false;
    const tbody = $('accounts');
    tbody.innerHTML = '';
    (d.accounts || []).forEach((a) => {
      const tr = document.createElement('tr');
      const state = a.disabled
        ? '<span class="pill bad">已停用</span>'
        : (a.cooling ? '<span class="pill bad">冷却中</span>' : '<span class="pill ok">可用</span>');
      const cells = [
        (a.name || a.uid) + '<br><span class="muted">' + a.uid + '</span>',
        state + (a.reason ? '<br><span class="muted">' + a.reason + '</span>' : ''),
        a.token_remaining || '—',
        String(a.models || 0),
        String(a.active || 0) + '/' + String(a.max_concurrent || 1),
      ];
      cells.forEach((html) => {
        const td = document.createElement('td');
        td.innerHTML = html;
        tr.appendChild(td);
      });
      const td = document.createElement('td');
      const toggle = document.createElement('button');
      toggle.textContent = a.disabled ? '启用' : '停用';
      toggle.onclick = async () => {
        try {
          await api('/panel/api/codearts/accounts/' + encodeURIComponent(a.uid) + (a.disabled ? '/enable' : '/disable'), { method: 'POST' });
          await load();
        } catch (e) { msg(e.message, true); }
      };
      const del = document.createElement('button');
      del.className = 'danger';
      del.textContent = '删除';
      del.style.marginLeft = '6px';
      del.onclick = async () => {
        if (!window.confirm('删除账号 ' + (a.name || a.uid) + '？')) return;
        try {
          await api('/panel/api/codearts/accounts/' + encodeURIComponent(a.uid), { method: 'DELETE' });
          await load();
        } catch (e) { msg(e.message, true); }
      };
      td.appendChild(toggle);
      td.appendChild(del);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
    $('modelInfo').textContent = '模型目录：' + (d.model_count || 0) + ' 条；启用的账号：' + (d.accounts || []).filter((a) => !a.disabled).length + ' 个。';
  }

  async function save() {
    const cfg = {
      enabled: $('enabled').checked,
      timeout_seconds: Number($('timeout').value || 30),
      stream_timeout_seconds: Number($('stream_timeout').value || 600),
      models_ttl_seconds: Number($('models_ttl').value || 300),
      max_concurrent: Number($('max_concurrent').value || 1),
      busy_wait_seconds: Number($('busy_wait').value || 0),
      benefit_auto_claim: $('benefit_auto_claim').checked,
    };
    try {
      await api('/panel/api/codearts/config', { method: 'POST', body: JSON.stringify(cfg) });
      msg('已保存。');
      await load();
    } catch (e) { msg(e.message, true); }
  }

  async function startOAuth() {
    try {
      const d = await api('/panel/api/codearts/oauth/start', { method: 'POST' });
      showOAuth(d.auth_url);
      if (d.session_id) pollOAuth(d.session_id);
    } catch (e) { msg(e.message, true); }
  }

  async function refreshModels() {
    try {
      msg('正在向上游刷新模型目录…');
      await api('/panel/api/codearts/models/refresh', { method: 'POST' });
      msg('模型目录已刷新。');
      await load();
    } catch (e) { msg(e.message, true); }
  }

  $('save').onclick = save;
  $('add').onclick = startOAuth;
  $('refresh_models').onclick = refreshModels;
  $('reload').onclick = () => load().catch((e) => msg(e.message, true));
  load().catch((e) => msg(e.message, true));
})();