# app.py
from flask import Flask, render_template_string

app = Flask(__name__)

PAGE = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>OWASP Top 10 Interactive Simulator (Safe)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root { --bg:#0a1428; --panel:#0f1f3d; --border:#1d3b72; --text:#eaf2ff; --muted:#a7c4ff; --good:#38d39f; --warn:#ffd97a; --bad:#ff6b6b }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; }
    header { padding:16px; background:linear-gradient(90deg,#0e2e57,#0f3f86,#0b6fb1); display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap }
    h1 { margin:0; font-size:20px }
    .small { color:var(--muted); font-size:12px }
    main { padding:16px }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:12px }
    .card { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:12px }
    .title { display:flex; justify-content:space-between; align-items:center; gap:8px }
    .pill { padding:2px 8px; border-radius:999px; border:1px solid var(--border); color:var(--muted); font-size:12px }
    .btn { padding:8px 10px; border-radius:10px; border:1px solid #2c4d85; background:#134a9a; color:#fff; cursor:pointer }
    .btn.ghost { background:transparent }
    .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin:8px 0 }
    input, select, textarea { width:100%; padding:8px; border-radius:8px; border:1px solid var(--border); background:#0a1735; color:var(--text) }
    .out { margin-top:8px; padding:8px; border-radius:10px; background:#08132b; border:1px solid var(--border); white-space:pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px }
    .status { font-size:12px }
    .ok { color: var(--good) }
    .warn { color: var(--warn) }
    .bad { color: var(--bad) }
    .mt8 { margin-top:8px }
    footer { padding:12px 16px; color:var(--muted) }
    details > summary { cursor:pointer; margin:6px 0; }
    ul.fix { margin:6px 0 0 16px }
    .kbd { background:#06122a; border:1px solid var(--border); padding:0 6px; border-radius:6px }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>OWASP Top 10 — Interactive Simulator (Safe)</h1>
      <div class="small">Hands-on mini-labs that explain each risk with instant, safe simulations—no backend calls, works offline.</div>
    </div>
    <div class="row">
      <button class="btn" onclick="resetAll()">Reset all</button>
      <span class="pill">Developer: Abdallah Alkhatib</span>
    </div>
  </header>

  <main class="grid" id="grid"></main>

  <footer>
    <div>Built for learning: outputs are simulations only (no exploit code, no external requests).</div>
  </footer>

<script>
/* ========= Core utilities ========= */
function escapeHtml(s){return (s||'').replace(/[&<>"'`]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c]));}
function set(el, html){el.innerHTML = html;}
function text(el, t){el.textContent = t;}
function codeBlock(lines){return '<div class="out">'+escapeHtml(lines.join('\\n'))+'</div>';}

/* ========= Scenarios =========
  Each item returns { id, title, ui(container), run(container) }
  UI builds inputs; run reads inputs and prints result + explanation + fixes.
*/

/* A01 Broken Access Control */
function A01(container){
  const html = `
    <div class="title"><strong>A01 — Broken Access Control</strong><span class="pill">AuthZ</span></div>
    <div class="row"><label>Role:
      <select id="a01-role">
        <option value="guest">guest</option>
        <option value="user">user</option>
        <option value="admin">admin</option>
      </select></label>
    </div>
    <div class="row"><label>Action:
      <select id="a01-action">
        <option value="view_profile">view_profile</option>
        <option value="delete_user">delete_user</option>
        <option value="export_audit_log">export_audit_log</option>
      </select></label>
    </div>
    <div class="row">
      <button class="btn" onclick="A01_run(this)">Test access</button>
      <span class="status" id="a01-status"></span>
    </div>
    <div id="a01-out" class="out"></div>
    <details class="mt8"><summary>Why this matters & how to fix</summary>
      <ul class="fix">
        <li>Enforce <b>server-side authorization</b> checks for every request, not just UI buttons.</li>
        <li>Use <b>deny-by-default</b> and explicit allow rules per role/permission.</li>
        <li>Log & alert on access control violations.</li>
      </ul>
    </details>`;
  set(container, html);
}
function A01_run(btn){
  const role = document.getElementById('a01-role').value;
  const action = document.getElementById('a01-action').value;
  const status = document.getElementById('a01-status');
  const out = document.getElementById('a01-out');

  // Safe simulated policy
  const allow = {
    guest: ['view_profile'],
    user:  ['view_profile'],
    admin: ['view_profile','delete_user','export_audit_log']
  };
  const allowed = (allow[role]||[]).includes(action);

  status.className = 'status ' + (allowed ? 'ok' : 'bad');
  status.textContent = allowed ? 'Allowed (policy)' : 'Denied (policy)';
  const lines = [
    `request: role=${role} action=${action}`,
    `enforce: server_authorize(role, action)`,
    `result: ${allowed ? 'ALLOW' : 'DENY'}`
  ];
  set(out, escapeHtml(lines.join('\n')));
}

/* A02 Cryptographic Failures */
function A02(container){
  const html = `
    <div class="title"><strong>A02 — Cryptographic Failures</strong><span class="pill">Crypto</span></div>
    <div class="row"><label>Secret to store:
      <input id="a02-secret" placeholder="e.g., MyP@ssw0rd!" /></label>
    </div>
    <div class="row">
      <label><input type="checkbox" id="a02-hash" checked> Hash with salt (good)</label>
      <label><input type="checkbox" id="a02-plain"> Store plaintext (bad)</label>
    </div>
    <div class="row"><button class="btn" onclick="A02_run()">Store</button></div>
    <div id="a02-out" class="out"></div>
    <details class="mt8"><summary>Why this matters & how to fix</summary>
      <ul class="fix">
        <li>Never store secrets in plaintext; use strong <b>hashing with salt</b> (e.g., bcrypt/Argon2).</li>
        <li>Use TLS; disable weak ciphers/protocols; rotate keys; protect key material.</li>
      </ul>
    </details>`;
  set(container, html);
}
function A02_run(){
  const s = document.getElementById('a02-secret').value || '';
  const hash = document.getElementById('a02-hash').checked;
  const plain = document.getElementById('a02-plain').checked;
  const lines = [];
  if (hash){
    // demo-only fake "hash" (do NOT use for real crypto)
    const salt = 'NaCl';
    const fakeHash = btoa(unescape(encodeURIComponent(s+':'+salt))).slice(0,32);
    lines.push(`bcrypt(salt, secret) -> ${fakeHash}…  (simulated)`);
  }
  if (plain){
    lines.push(`PLAINTEXT -> ${s}  ❌ Do not store plaintext secrets`);
  }
  if (!hash && !plain) lines.push('Nothing selected. Choose at least one option.');
  set(document.getElementById('a02-out'), escapeHtml(lines.join('\n')));
}

/* A03 Injection */
function A03(container){
  const html = `
    <div class="title"><strong>A03 — Injection</strong><span class="pill">Input</span></div>
    <div class="row"><label>Search term:
      <input id="a03-q" placeholder="O'Reilly or 1=1" /></label></div>
    <div class="row">
      <label><input type="radio" name="a03mode" value="concat" checked> Concatenate (bad)</label>
      <label><input type="radio" name="a03mode" value="param"> Parameterized (good)</label>
    </div>
    <div class="row"><button class="btn" onclick="A03_run()">Run</button></div>
    <div id="a03-out" class="out"></div>
    <details class="mt8"><summary>Why this matters & how to fix</summary>
      <ul class="fix">
        <li>Use <b>parameterized queries</b>/ORM. Never build SQL/LDAP/NoSQL by string concatenation.</li>
        <li>Validate/normalize inputs; use proper encoding at the sink.</li>
      </ul>
    </details>`;
  set(container, html);
}
function A03_run(){
  const q = document.getElementById('a03-q').value || '';
  const mode = [...document.querySelectorAll('[name="a03mode"]')].find(x=>x.checked).value;
  let lines = [];
  if (mode === 'concat'){
    const sql = "SELECT * FROM books WHERE title LIKE '%"+q+"%'";
    const risky = /'|;|--|\bOR\b|\bAND\b|=/i.test(q);
    lines.push(sql);
    lines.push(risky ? "⚠️ Potential injection pattern detected. This is why concatenation is dangerous." :
                        "Still risky: concatenation lets attackers craft input that alters the query.");
  } else {
    lines.push("SELECT * FROM books WHERE title LIKE ?  -- safe (prepared)");
    lines.push("params = ['%"+q.replace(/'/g,"''")+"%']");
  }
  set(document.getElementById('a03-out'), escapeHtml(lines.join('\n')));
}

/* A04 Insecure Design */
function A04(container){
  const html = `
    <div class="title"><strong>A04 — Insecure Design</strong><span class="pill">Architecture</span></div>
    <div class="row">
      <label>Recovery flow requires MFA? <input type="checkbox" id="a04-mfa"></label>
      <label>Rate limit recovery attempts? <input type="checkbox" id="a04-rate" checked></label>
    </div>
    <div class="row"><button class="btn" onclick="A04_run()">Assess design</button></div>
    <div id="a04-out" class="out"></div>
    <details class="mt8"><summary>Why this matters & how to fix</summary>
      <ul class="fix">
        <li>Do <b>threat modeling</b> and define <b>abuse cases</b> early.</li>
        <li>Apply <b>defense-in-depth</b> patterns (MFA, rate limits, monitoring, verification).</li>
      </ul>
    </details>`;
  set(container, html);
}
function A04_run(){
  const mfa = document.getElementById('a04-mfa').checked;
  const rate = document.getElementById('a04-rate').checked;
  const risk = (!mfa && !rate) ? 'HIGH' : (!mfa || !rate) ? 'MEDIUM' : 'LOW';
  const lines = [
    `Design check — recovery: MFA=${mfa}, rate_limit=${rate}`,
    `Risk (simulated): ${risk}`,
    (risk==='HIGH'?'Add MFA & rate-limits':'Looks better; validate additional controls (notifications, proofs).')
  ];
  set(document.getElementById('a04-out'), escapeHtml(lines.join('\n')));
}

/* A05 Security Misconfiguration */
function A05(container){
  const html = `
    <div class="title"><strong>A05 — Security Misconfiguration</strong><span class="pill">Config</span></div>
    <div class="row">
      <label><input type="checkbox" id="a05-dirlist"> Directory listing enabled</label>
      <label><input type="checkbox" id="a05-admin" checked> Admin panel public</label>
      <label><input type="checkbox" id="a05-csp" checked> CSP header set</label>
    </div>
    <div class="row"><button class="btn" onclick="A05_run()">Audit</button></div>
    <div id="a05-out" class="out"></div>
    <details class="mt8"><summary>Fix checklist</summary>
      <ul class="fix">
        <li>Disable directory listing; hide stack traces.</li>
        <li>Restrict admin paths (VPN, IP allowlists, MFA).</li>
        <li>Set headers: CSP, HSTS, X-Frame-Options, etc.</li>
      </ul>
    </details>`;
  set(container, html);
}
function A05_run(){
  const dir = document.getElementById('a05-dirlist').checked;
  const admin = document.getElementById('a05-admin').checked;
  const csp = document.getElementById('a05-csp').checked;
  const issues = [];
  if (dir) issues.push('Directory listing exposes files.');
  if (admin) issues.push('Admin panel reachable from public internet.');
  if (!csp) issues.push('Missing CSP header.');
  const grade = issues.length===0?'PASS':issues.length===1?'WARN':'FAIL';
  const lines = [`Config grade: ${grade}`, ...(issues.length?issues:['No obvious misconfigurations found.'])];
  set(document.getElementById('a05-out'), escapeHtml(lines.join('\n')));
}

/* A06 Vulnerable & Outdated Components */
function A06(container){
  const html = `
    <div class="title"><strong>A06 — Vulnerable & Outdated Components</strong><span class="pill">Deps</span></div>
    <div class="row"><label>Component:
      <select id="a06-comp">
        <option>web-framework 2.0.1</option>
        <option>templating 1.4.0</option>
        <option>auth-lib 0.9.3</option>
      </select></label>
    </div>
    <div class="row"><button class="btn" onclick="A06_run()">Scan SBOM</button></div>
    <div id="a06-out" class="out"></div>
    <details class="mt8"><summary>Good practice</summary>
      <ul class="fix">
        <li>Maintain an SBOM and run SCA in CI/CD; monitor CVEs.</li>
        <li>Patch regularly; use supported versions.</li>
      </ul>
    </details>`;
  set(container, html);
}
function A06_run(){
  const comp = document.getElementById('a06-comp').value;
  const map = {
    'web-framework 2.0.1': 'CVE-2024-12345 — Template sandbox bypass (HIGH)',
    'templating 1.4.0': 'No known issues (as of this demo)',
    'auth-lib 0.9.3': 'CVE-2023-8080 — Token validation flaw (CRITICAL)'
  };
  const msg = map[comp] || 'No data';
  set(document.getElementById('a06-out'), escapeHtml(`SBOM check -> ${msg}\nAdvice: upgrade to the latest patched version.`));
}

/* A07 Identification & Authentication Failures */
function A07(container){
  const html = `
    <div class="title"><strong>A07 — Identification & Authentication Failures</strong><span class="pill">AuthN</span></div>
    <div class="row"><label>Username <input id="a07-u" placeholder="user@example.com"></label></div>
    <div class="row"><label>Password <input id="a07-p" type="password" placeholder="••••••••"></label></div>
    <div class="row">
      <label><input type="checkbox" id="a07-mfa" checked> MFA required</label>
      <label><input type="checkbox" id="a07-lock" checked> Lockout after 5 attempts</label>
    </div>
    <div class="row"><button class="btn" onclick="A07_run()">Login (sim)</button></div>
    <div id="a07-out" class="out"></div>
    <details class="mt8"><summary>Strengthen auth</summary>
      <ul class="fix">
        <li>Require MFA for sensitive actions.</li>
        <li>Use secure password storage; add lockout and alerts.</li>
        <li>Secure session cookies: HttpOnly, Secure, SameSite.</li>
      </ul>
    </details>`;
  set(container, html);
}
let A07_attempts = 0;
function A07_run(){
  const mfa = document.getElementById('a07-mfa').checked;
  const lock = document.getElementById('a07-lock').checked;
  A07_attempts++;
  const locked = lock && A07_attempts > 5;
  const ok = !locked && mfa; // demo-only: require MFA
  const lines = [
    `attempt=${A07_attempts} locked=${locked} mfa=${mfa}`,
    ok ? 'Login OK (simulated)' : (locked ? 'Account locked (simulated)' : 'Login denied: MFA required (simulated)'),
  ];
  set(document.getElementById('a07-out'), escapeHtml(lines.join('\n')));
}

/* A08 Software & Data Integrity Failures */
function A08(container){
  const html = `
    <div class="title"><strong>A08 — Software & Data Integrity Failures</strong><span class="pill">Integrity</span></div>
    <div class="row"><label>Package name <input id="a08-pkg" placeholder="widget-core"></label></div>
    <div class="row"><label>Signature provided? <input type="checkbox" id="a08-sig" checked></label></div>
    <div class="row"><button class="btn" onclick="A08_run()">Verify</button></div>
    <div id="a08-out" class="out"></div>
    <details class="mt8"><summary>Best practices</summary>
      <ul class="fix">
        <li>Verify signatures/hashes for updates & releases.</li>
        <li>Protect the build pipeline; guard secrets; enforce signed artifacts.</li>
      </ul>
    </details>`;
  set(container, html);
}
function A08_run(){
  const pkg = document.getElementById('a08-pkg').value || 'widget-core';
  const sig = document.getElementById('a08-sig').checked;
  const lines = [
    `pkg=${pkg} signature=${sig}`,
    sig ? 'Verification OK (simulated: signature trusted)' : 'Blocked: missing signature (simulated)'
  ];
  set(document.getElementById('a08-out'), escapeHtml(lines.join('\n')));
}

/* A09 Security Logging & Monitoring Failures */
function A09(container){
  const html = `
    <div class="title"><strong>A09 — Security Logging & Monitoring Failures</strong><span class="pill">Observability</span></div>
    <div class="row">
      <label><input type="checkbox" id="a09-auth" checked> Log auth events</label>
      <label><input type="checkbox" id="a09-admin" checked> Alert on admin changes</label>
      <label><input type="checkbox" id="a09-sync"> NTP time sync</label>
    </div>
    <div class="row"><button class="btn" onclick="A09_run()">Simulate incident</button></div>
    <div id="a09-out" class="out"></div>
    <details class="mt8"><summary>Improve detection</summary>
      <ul class="fix">
        <li>Centralize logs; include authn/authz/admin.</li>
        <li>Baseline & alert on anomalies; keep time synchronized.</li>
      </ul>
    </details>`;
  set(container, html);
}
function A09_run(){
  const auth = document.getElementById('a09-auth').checked;
  const admin = document.getElementById('a09-admin').checked;
  const ntp = document.getElementById('a09-sync').checked;
  const gaps = [];
  if (!auth) gaps.push('Auth events missing');
  if (!admin) gaps.push('No alert on admin actions');
  if (!ntp) gaps.push('Clock not synchronized');
  const ready = gaps.length===0;
  const lines = [
    `Incident: privilege change at 12:01`,
    ready ? '✅ Detected & alerted (simulated)' : '⚠️ Missed signals: '+gaps.join(', ')
  ];
  set(document.getElementById('a09-out'), escapeHtml(lines.join('\n')));
}

/* A10 Server-Side Request Forgery (SSRF) */
function A10(container){
  const html = `
    <div class="title"><strong>A10 — SSRF</strong><span class="pill">Egress</span></div>
    <div class="row">
      <label>Target URL <input id="a10-url" placeholder="https://api.example.com/info"></label>
    </div>
    <div class="row">
      <label>Egress policy:
        <select id="a10-pol">
          <option value="allowall">Allow all (bad)</option>
          <option value="allowlist" selected>Allowlist domains (good)</option>
        </select>
      </label>
    </div>
    <div class="row"><button class="btn" onclick="A10_run()">Fetch (sim)</button></div>
    <div id="a10-out" class="out"></div>
    <details class="mt8"><summary>Mitigations</summary>
      <ul class="fix">
        <li>Enforce egress allowlists; block access to metadata/internal networks.</li>
        <li>Normalize/validate URLs; use safe libraries; add network-level protections.</li>
      </ul>
    </details>`;
  set(container, html);
}
function A10_run(){
  const url = (document.getElementById('a10-url').value || '').trim();
  const pol = document.getElementById('a10-pol').value;
  const internal = /^https?:\/\/(169\.254\.169\.254|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/i.test(url);
  const allow = pol==='allowall' ? true : /^(https?:\/\/)?(api\.example\.com|public\.example\.org)/i.test(url);
  const allowed = allow && !internal;
  const lines = [
    `request -> ${url || '(empty)'}`,
    internal ? '⚠️ Internal/metadata address detected — blocked.' :
    allowed ? '✅ Allowed by allowlist.' : '❌ Not on allowlist — blocked.',
  ];
  set(document.getElementById('a10-out'), escapeHtml(lines.join('\n')));
}

/* ========= App wiring ========= */
const SCENES = [
  {id:'A01', title:'Broken Access Control', ui:A01},
  {id:'A02', title:'Cryptographic Failures', ui:A02},
  {id:'A03', title:'Injection', ui:A03},
  {id:'A04', title:'Insecure Design', ui:A04},
  {id:'A05', title:'Security Misconfiguration', ui:A05},
  {id:'A06', title:'Vulnerable & Outdated Components', ui:A06},
  {id:'A07', title:'Identification & Authentication Failures', ui:A07},
  {id:'A08', title:'Software & Data Integrity Failures', ui:A08},
  {id:'A09', title:'Security Logging & Monitoring Failures', ui:A09},
  {id:'A10', title:'Server-Side Request Forgery (SSRF)', ui:A10},
];

function boot(){
  const grid = document.getElementById('grid');
  grid.innerHTML = '';
  for (const s of SCENES){
    const card = document.createElement('section');
    card.className = 'card';
    grid.appendChild(card);
    s.ui(card);
  }
}
function resetAll(){ boot(); }
boot();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(PAGE)

if __name__ == "__main__":
    # No debug reloader (to avoid odd host behaviors), single process works everywhere.
    app.run(host="0.0.0.0", port=5000, debug=False)
