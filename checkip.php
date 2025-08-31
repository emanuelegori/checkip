<?php
/************************************************************
 * EG Check IP / Connectivity - Versione migliorata agosto 2025
 ************************************************************/

date_default_timezone_set('Europe/Rome');
$SITE_HOST     = 'emanuelegori.uno';
$NM_OK_STRING  = 'Connessione attiva';
$NM_SECRET_KEY = '9f1c0a7e5b3d2a48c6e4f1b09a7d53c1e2f4a6b8c0d9e7f3a5b1c2d3e4f5a6b7'; // cambia se vuoi
$SHORT_WINDOW  = 10;   // sec (plain/html/json)
$HOURLY_LIMIT  = 60;   // richieste/ora/IP
$NM_SHORT_WIN  = 10;   // sec (endpoint NM)
$NM_HOURLY_LIM = 120;  // richieste/ora/IP per NM
$V4_HOST       = 'v4.emanuelegori.uno'; // AAAA assente
$V6_HOST       = 'v6.emanuelegori.uno'; // A assente

header('Access-Control-Allow-Origin: *');
header('Vary: Origin');
header('Cache-Control: no-store');

function is_public_ipv4($ip){ return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE); }
function is_public_ipv6($ip){ return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE); }
function client_ip(){
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $xff    = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    $is_proxy = preg_match('~^(127\.0\.0\.1|::1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)~', $remote);
    if ($is_proxy && $xff){
        $first = trim(explode(',', $xff)[0]);
        if (is_public_ipv4($first) || is_public_ipv6($first)) return $first;
    }
    return $remote ?: '0.0.0.0';
}
function touch_dir($dir){ if(!is_dir($dir)) @mkdir($dir, 0777, true); }
function rl_path($ip, $bucket){
    $safe = preg_replace('/[^0-9a-fA-F:._-]/', '_', $ip);
    $dir  = sys_get_temp_dir() . '/eg_checkip_rl';
    touch_dir($dir);
    if ($bucket === 'short') {
        return "$dir/short_{$safe}.ts";
    } else {
        $hour = (string)floor(time()/3600);
        return "$dir/hour_{$safe}_{$hour}.cnt";
    }
}
function rate_limit($ip, $is_nm = false){
    $now   = time();
    $s_win = $is_nm ? $GLOBALS['NM_SHORT_WIN'] : $GLOBALS['SHORT_WINDOW'];
    $h_lim = $is_nm ? $GLOBALS['NM_HOURLY_LIM'] : $GLOBALS['HOURLY_LIMIT'];
    $short = rl_path($ip, 'short');
    $last  = @file_exists($short) ? intval(@file_get_contents($short)) : 0;
    if ($last && ($now - $last) < $s_win) {
        return ['blocked' => true, 'reason' => 'short'];
    }
    @file_put_contents($short, (string)$now, LOCK_EX);
    $hour = rl_path($ip, 'hour');
    $cnt  = @file_exists($hour) ? intval(@file_get_contents($hour)) : 0;
    $cnt++;
    @file_put_contents($hour, (string)$cnt, LOCK_EX);
    if ($cnt > $h_lim) {
        return ['blocked' => true, 'reason' => 'hour'];
    }
    return ['blocked' => false];
}
function it_datetime_parts(){
    $tz = new DateTimeZone('Europe/Rome');
    $dt = new DateTime('now', $tz);
    $abbr = $dt->format('T');
    $offsetMin = $tz->getOffset($dt) / 60;
    $sign = $offsetMin >= 0 ? '+' : '-';
    $hh = str_pad((string)floor(abs($offsetMin)/60), 2, '0', STR_PAD_LEFT);
    $mm = str_pad((string)(abs($offsetMin)%60), 2, '0', STR_PAD_LEFT);
    $utc = "UTC{$sign}{$hh}:{$mm}";
    $iso = $dt->format('c');
    if (class_exists('IntlDateFormatter')) {
        $fmt = new IntlDateFormatter('it_IT', IntlDateFormatter::FULL, IntlDateFormatter::MEDIUM, 'Europe/Rome', IntlDateFormatter::GREGORIAN, "EEEE d MMMM y HH:mm:ss");
        $human = $fmt->format($dt);
    } else {
        $human = $dt->format('d/m/Y H:i:s');
    }
    return [$human, $abbr, $utc, $iso];
}

$ip       = client_ip();
$ua       = $_SERVER['HTTP_USER_AGENT'] ?? '';
$isCurl   = stripos($ua, 'curl') !== false;
$isPlain  = isset($_GET['plain']) || $isCurl;
$isJSON   = isset($_GET['json']);
$isNM     = isset($_GET['nm']);
$ipVer    = strpos($ip, ':') !== false ? 'IPv6' : 'IPv4';
[$humanTS, $tzAbbr, $utcOff, $isoTS] = it_datetime_parts();

// $logLine = sprintf("[%s] %s\t%s\t%s\t%s%s%s\n", $isoTS, $ip, $ipVer, ($ua ?: '-'), $isPlain?' plain':'', $isJSON?' json':'', $isNM?' nm':'');
// @file_put_contents(__DIR__ . '/checkip.log', $logLine, FILE_APPEND);

if ($isNM) {
    $key = $_GET['k'] ?? '';
    if (!hash_equals($NM_SECRET_KEY, (string)$key)) {
        header('Content-Type: text/plain; charset=UTF-8', true, 403);
        echo "forbidden\n";
        exit;
    }
    $rl = rate_limit($ip, true);
    header('Content-Type: text/plain; charset=UTF-8');
    if ($rl['blocked'] ?? false) {
        if (($rl['reason'] ?? '') === 'short') { echo "wait 10s\n"; }
        else { echo "rate limit hour\n"; }
        exit;
    }
    echo $NM_OK_STRING;
    exit;
}

if ($isPlain) {
    $rl = rate_limit($ip);
    header('Content-Type: text/plain; charset=UTF-8');
    if ($rl['blocked'] ?? false) {
        if (($rl['reason'] ?? '') === 'short') { echo "wait 10s\n"; }
        else { echo "rate limit hour\n"; }
        exit;
    }
    echo $ip . "\n";
    exit;
}

if ($isJSON) {
    $rl = rate_limit($ip);
    header('Content-Type: application/json; charset=UTF-8');
    if ($rl['blocked'] ?? false) {
        $err = (($rl['reason'] ?? '') === 'short') ? 'wait 10s' : 'rate limit hour';
        echo json_encode(['ok'=>false,'error'=>$err], JSON_UNESCAPED_UNICODE);
        exit;
    }
    echo json_encode([
        'ok'         => true,
        'ip'         => $ip,
        'version'    => $ipVer,
        'timestamp'  => $humanTS,
        'iso'        => $isoTS,
        'timezone'   => $tzAbbr,
        'utc_offset' => $utcOff,
        'user_agent' => $ua,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

?>
<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<title>EG Check IP / Connectivity</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="https://<?= $SITE_HOST ?>/favicon.svg" type="image/svg+xml">
<style>
:root {
  --bg:#f6f7f9; --fg:#1b1f23; --muted:#6b7280; --card:#ffffff; --shadow:0 8px 30px rgba(0,0,0,.08); --accent:#2563eb; --ok:#10b981; --warn:#f59e0b; --badge:#eef2ff;
}
[data-theme="dark"] {
  --bg:#0b0f14;
  --fg:#e5e7eb;
  --muted:#9aa4b2;
  --card:#141b22;
  --shadow:0 8px 30px rgba(0,0,0,.45);
  --accent:#60a5fa;
  --ok:#3eea92;
  --warn:#ffbe3c;
  --badge:#222c37;
}


html,body{background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0}
.wrap{max-width:800px;margin:0 auto;padding:32px 10px}
.box{background:var(--card);border-radius:18px;box-shadow:var(--shadow);padding:28px 20px;margin:16px 0;transition:box-shadow .18s}
.box:hover{box-shadow:0 12px 32px rgba(37,99,235,.07);}
h1,h2{margin:0 0 10px;font-weight:700;}
.ip{font-size:22px;font-weight:700;letter-spacing:0.02em}
.badge{font-size:13px;border-radius:999px;padding:3px 10px;background:var(--badge);margin-left:8px}
.btn{border:1px solid var(--muted);background:var(--bg);color:var(--fg);padding:7px 12px;border-radius:12px;transition:background .18s;}
.btn:hover{background:var(--accent);color:#fff}
ul{padding-left:24px;}
ul li{margin-bottom:8px;line-height:1.6}
a{color:var(--accent);text-decoration:none;}
a:hover{text-decoration:underline;}
.muted{color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.k{color:var(--muted)}
.ok{color:var(--ok);} .warn{color:var(--warn);}
.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.right{display:flex;gap:10px;justify-content:flex-end}
.theme{display:flex;align-items:center;gap:10px}
.small{font-size:14px}
@media (max-width: 600px){
  .grid{grid-template-columns:1fr;}
  .box{padding:20px 8px;}
  h1{font-size:20px}
  .ip{font-size:18px}
}
</style>
</head>
<body>
<div class="wrap">
  <div class="row" style="justify-content:space-between;margin-bottom:8px">
    <div class="muted">EG Check IP</div>
    <div class="right">
      <div class="theme">
        <button id="themeBtn" class="btn" aria-label="Cambia tema">🌙 / ☀️</button>
      </div>
    </div>
  </div>

  <div class="box">
    <h1>🌐 Il tuo IP</h1>
    <p class="ip"><?= htmlspecialchars($ip) ?>
      <span class="badge"><?= htmlspecialchars($ipVer) ?></span>
    </p>
    <div class="grid">
      <div class="box">
        <p><strong>IPv4 pubblico</strong> <span id="v4badge" class="badge">probe</span></p>
        <p id="ip4" class="ip small">—</p>
      </div>
      <div class="box">
        <p><strong>IPv6 pubblico</strong> <span id="v6badge" class="badge">probe</span></p>
        <p id="ip6" class="ip small">—</p>
      </div>
    </div>
    <?php
      $uaShort = $ua ?: '—';
      echo '<p class="k">User-Agent: <span class="muted">'.htmlspecialchars($uaShort).'</span></p>';
      echo '<p class="k">Ora locale: <strong>'.htmlspecialchars($humanTS).'</strong> &middot; <span class="muted">'.htmlspecialchars($tzAbbr).' ('.htmlspecialchars($utcOff).')</span></p>';
      echo '<p class="k">ISO utente: <span class="muted">'.htmlspecialchars($isoTS).'</span></p>';
    ?>
  </div>

  <div class="box">
    <h2 style="margin:0 0 8px;display:flex;align-items:center;gap:8px">
      <svg width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle"><circle cx="12" cy="12" r="10" fill="#2563eb" opacity="0.15"/><path d="M12 8v4l3 3" stroke="#2563eb" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
      Come funziona
    </h2>
    <ul style="margin:0 0 10px 0">
      <li><b>Naviga con il browser:</b> visualizza il tuo IP pubblico e verifica IPv4/IPv6 in automatico.</li>
      <li><b>Usa <code>curl</code>:</b> ottieni solo l’IP, perfetto per script e check rapidi.<br>
        <code>curl https://<?= $SITE_HOST ?>/checkip</code> → solo IP<br>
        <code>curl -4 https://<?= $SITE_HOST ?>/checkip</code> → forza IPv4<br>
        <code>curl -6 https://<?= $SITE_HOST ?>/checkip</code> → forza IPv6<br>
 
      </li>
      <li><b>Formato testo:</b> aggiungi <code>?plain=1</code> per ricevere solo l’IP (<code>text/plain</code>).</li>
      <li><b>Formato JSON:</b> aggiungi <code>?json=1</code> per risposta strutturata (<code>application/json</code>).</li>
      <li><b>Monitoraggio NetworkManager:</b> usa <code>?nm=1&amp;k=CHIAVE</code> per risposta automatica “<?= htmlspecialchars($NM_OK_STRING) ?>”.</li>
    </ul>
    <p class="muted">
      Limiti: 1 richiesta ogni 10 secondi per IP, massimo 60/ora (rate separato per NetworkManager).
      <br>
      Servizio gratuito, nessun cookie né tracking. Se ti è utile, <a href="https://<?= $SITE_HOST ?>" target="_blank" rel="noopener nofollow">scopri di più sul progetto</a>!
    </p>
  </div>

  <p class="muted" style="text-align:center;margin-top:10px">
    Servizio offerto da
    <a href="https://<?= htmlspecialchars($SITE_HOST) ?>" target="_blank" rel="nofollow noopener"><?= htmlspecialchars($SITE_HOST) ?></a>
    • Nessun cookie, nessun tracking.
  </p>
</div>

<script>
// Tema: preferenza salvata o OS
(function(){
  const btn = document.getElementById('themeBtn');
  function setTheme(mode) {
    if (mode === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else if (mode === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem('eg-theme', mode);
    // Cambia icona in base al tema attivo
    btn.textContent = (mode === 'dark') ? '☀️' : '🌙';
  }
  // Ripristina preferenza salvata
  let mode = localStorage.getItem('eg-theme') || 'auto';
  // Se auto, scegli in base a sistema
  if (mode === 'auto') {
    mode = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  setTheme(mode);
  btn.addEventListener('click', function() {
    mode = (mode === 'dark') ? 'light' : 'dark';
    setTheme(mode);
  });
})();

// Probe IPv4/IPv6 usando sottodomini dedicati, badge con emoji
(function(){
  const ip4 = document.getElementById('ip4');
  const ip6 = document.getElementById('ip6');
  const b4  = document.getElementById('v4badge');
  const b6  = document.getElementById('v6badge');
  function probe(url, el, badge){
    fetch(url, {cache:'no-store', mode:'cors'})
      .then(r => r.ok ? r.text() : Promise.reject(r.status))
      .then(t => { el.textContent = t.trim(); badge.textContent='✅'; badge.classList.add('ok'); })
      .catch(_ => { el.textContent = 'non raggiungibile'; badge.textContent='🔴'; badge.classList.add('warn'); });
  }
  probe('https://<?= $V4_HOST ?>/checkip.php?plain=1', ip4, b4);
  probe('https://<?= $V6_HOST ?>/checkip.php?plain=1', ip6, b6);
})();
</script>
</body>
</html>
