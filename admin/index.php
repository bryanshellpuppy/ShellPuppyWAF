<?php
/*
 * PHP Web Application Firewall (WAF)
 * ----------------------------------
 * An open-source, customizable PHP WAF for protecting web applications
 * against common threats such as malicious bots, brute force, SQL injection, and more.
 *
 * This software is free and open source; you may use, modify, and distribute it
 * under the terms of the MIT License or any compatible open source license.
 * No warranty is provided.
 *
 * Created by ShellPuppy.com, 2025.
 * Project home: https://github.com/bryanshellpuppy/ShellPuppyWAF
 *
 * Attribution is appreciated but not required.
 */

session_start();

$configPath    = __DIR__ . '/../config.json';
$logPath       = __DIR__ . '/../logs/requests.log';
$botIpsPath    = __DIR__ . '/../bot_ips.txt';
$botCidrsPath  = __DIR__ . '/../bot_cidrs.txt';

// ===== Helper Functions =====
function loadConfig() {
    global $configPath;
    return json_decode(file_get_contents($configPath), true);
}
function saveConfig($data) {
    global $configPath;
    file_put_contents($configPath, json_encode($data, JSON_PRETTY_PRINT));
}
function loadFileOrBlank($path) {
    return file_exists($path) ? file_get_contents($path) : '';
}
function saveFile($path, $contents) {
    file_put_contents($path, $contents);
}

// ===== Authentication =====
$config = loadConfig();
if (!isset($_SESSION['waf_admin'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pw']) && $_POST['pw'] === $config['admin_password']) {
        $_SESSION['waf_admin'] = true;
        header("Location: {$_SERVER['PHP_SELF']}");
        exit;
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>WAF Admin Login</title>
        <style>
            body {font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#f8f9fa;}
            form {background:#fff;padding:2rem 2rem 1.5rem 2rem;border-radius:14px;box-shadow:0 0 20px #0001;}
            input[type=password],button {font-size:1.1rem;padding:0.5rem 1rem;margin-top:1rem;width:100%;border-radius:6px;}
            button {background:#3887f6;color:white;border:none;cursor:pointer;}
            button:hover {background:#225bb0;}
        </style>
    </head>
    <body>
        <form method="post">
            <h2 style="margin-top:0;">WAF Admin Login</h2>
            <input type="password" name="pw" placeholder="Admin Password" autofocus required>
            <button>Login</button>
        </form>
    </body>
    </html>
    <?php
    exit;
}

// ===== Handle AJAX log fetch =====
if (isset($_GET['ajax']) && $_GET['ajax'] === "log") {
    header("Content-Type: text/plain");
    if (file_exists($logPath)) {
        $lines = file($logPath);
        $out = [];
        foreach (array_reverse($lines) as $line) {
            $entry = json_decode($line, true);
            if ($entry) {
                $out[] = "[" . $entry['time'] . "] " . $entry['ip'] . " " . $entry['ua'] . " " . $entry['uri'] . " [" . $entry['reason'] . "]";
            }
        }
        echo implode("\n", $out);
    } else {
        echo "No log entries.";
    }
    exit;
}

// ===== Clear Logs =====
if (isset($_POST['clear_logs']) && $_POST['clear_logs'] === "1") {
    file_put_contents($logPath, '');
    header("Location: {$_SERVER['PHP_SELF']}");
    exit;
}

// ===== Save Config =====
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_config'])) {
    $fields = [
        'blocked_ips', 'whitelisted_ips', 'blocked_agents', 'sql_patterns', 'xss_patterns',
        'rate_limit', 'rate_window_seconds', 'captcha_enabled', 'captcha_frequency'
    ];
    foreach ($fields as $f) {
        if (isset($_POST[$f])) {
            if ($f === 'captcha_enabled') {
                $config[$f] = $_POST[$f] == "1";
            } else if ($f === 'captcha_frequency') {
                $config[$f] = max(1, (int)$_POST[$f]);
            } else if (is_array($config[$f])) {
                $config[$f] = array_filter(array_map('trim', explode("\n", $_POST[$f])));
            } else {
                $config[$f] = (int)$_POST[$f];
            }
        }
    }
    if (!empty($_POST['admin_password'])) $config['admin_password'] = $_POST['admin_password'];
    saveConfig($config);
    $msg = "Config saved!";
}

// ===== Save Bot IPs =====
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_bot_ips'])) {
    saveFile($botIpsPath, trim($_POST['bot_ips']));
    $msg = "Bot IPs updated!";
}

// ===== Save Bot CIDRs =====
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_bot_cidrs'])) {
    saveFile($botCidrsPath, trim($_POST['bot_cidrs']));
    $msg = "Bot CIDRs updated!";
}

// ===== Prepare data for UI =====
$botIpsText = htmlspecialchars(loadFileOrBlank($botIpsPath));
$botCidrsText = htmlspecialchars(loadFileOrBlank($botCidrsPath));

?>
<!DOCTYPE html>
<html>
<head>
    <title>PHP WAF Admin Panel</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        body {font-family:sans-serif;background:#f4f6fb;margin:0;}
        .container {max-width:1080px;margin:2rem auto 0 auto;padding:2rem;background:white;box-shadow:0 0 32px #0002;border-radius:18px;}
        h2 {margin-top:0;color:#2851a3;}
        label {display:block;margin-top:15px;font-weight:600;}
        textarea,input[type=number],input[type=password],select {width:100%;padding:8px;border-radius:7px;border:1px solid #ccd;}
        textarea {height:60px;}
        input[type=number] {width:100px;}
        input[type=password] {margin-bottom:8px;}
        select {width:auto;min-width:90px;}
        .row {display:flex;gap:2rem;flex-wrap:wrap;}
        .col {flex:1 1 350px;}
        button {padding:9px 18px;border:none;border-radius:7px;background:#3887f6;color:#fff;font-weight:bold;font-size:1rem;cursor:pointer;margin-top:12px;}
        button:hover {background:#225bb0;}
        .success {color:green;margin:0.7rem 0;}
        .log-controls {display:flex;gap:10px;align-items:center;}
        .logsbox {background:#f0f3fa;border-radius:8px;padding:1rem;font-family:monospace;font-size:1rem;height:260px;overflow:auto;margin-top:8px;}
        .botlistbox {background:#fafbfc;border-radius:8px;padding:1rem;}
        .logo-wrap {text-align:center;margin-bottom:1.5rem;}
        .botlinks {margin-top:8px;}
        .botlinks button, .botlinks a {background:#46c4ff;color:#222; border:none;padding:7px 18px;border-radius:7px;cursor:pointer;font-weight:600;margin-right:10px;text-decoration:none;display:inline-block;}
        .botlinks button:hover, .botlinks a:hover {background:#2693c2;color:#fff;}
        .footer {margin-top:3rem;text-align:center;font-size:1.1em;color:#888;}
        @media (max-width: 800px) {.row {flex-direction:column;}}
    </style>
</head>
<body>
<div class="container">
    <div class="logo-wrap">
        <img src="logo.png" alt="ShellPuppy.com" style="max-width:220px;width:60vw;height:auto;opacity:0.97;">
    </div>
    <h2>ShellPuppy PHP WAF - Admin Panel</h2>
    <?php if (isset($msg)) echo "<div class='success'>$msg</div>"; ?>

    <form method="post" class="row" autocomplete="off">
        <div class="col">
            <label>Blocked IPs or CIDR blocks (one per line):
                <textarea name="blocked_ips"><?=htmlspecialchars(implode("\n",$config['blocked_ips'] ?? []))?></textarea>
            </label>
            <label>Whitelisted IPs or CIDR blocks (one per line):
                <textarea name="whitelisted_ips"><?=htmlspecialchars(implode("\n",$config['whitelisted_ips'] ?? []))?></textarea>
            </label>
            <label>Blocked User-Agents (one per line):
                <textarea name="blocked_agents"><?=htmlspecialchars(implode("\n",$config['blocked_agents'] ?? []))?></textarea>
            </label>
        </div>
        <div class="col">
            <label>SQLi Patterns (one per line):
                <textarea name="sql_patterns"><?=htmlspecialchars(implode("\n",$config['sql_patterns'] ?? []))?></textarea>
            </label>
            <label>XSS Patterns (one per line):
                <textarea name="xss_patterns"><?=htmlspecialchars(implode("\n",$config['xss_patterns'] ?? []))?></textarea>
            </label>
            <label>Rate Limit:
                <input type="number" name="rate_limit" value="<?=htmlspecialchars($config['rate_limit'] ?? 0)?>">
                <span style="font-weight:normal;">requests per window</span>
            </label>
            <label>Window (seconds):
                <input type="number" name="rate_window_seconds" value="<?=htmlspecialchars($config['rate_window_seconds'] ?? 600)?>">
            </label>
            <label>
                Human Check (CAPTCHA):
                <select name="captcha_enabled">
                    <option value="1" <?=!empty($config['captcha_enabled']) ? "selected" : ""?>>On</option>
                    <option value="0" <?=empty($config['captcha_enabled']) ? "selected" : ""?>>Off</option>
                </select>
            </label>
            <label>
                CAPTCHA Frequency:
                <input type="number" name="captcha_frequency" min="1" max="1000" value="<?=htmlspecialchars($config['captcha_frequency'] ?? 20)?>">
                <span style="font-weight:normal;">(1 in N requests)</span>
            </label>
            <label>Admin Password:
                <input type="password" name="admin_password" value="" placeholder="Leave blank to keep current">
            </label>
            <button name="save_config" value="1" style="margin-top:15px;">Save Config</button>
        </div>
    </form>

    <div style="margin-top:2.5rem;">
        <h3 style="margin-bottom:0.5rem;">Upload, Edit or Download Bot Block Lists</h3>
        <div class="row" style="gap:2.5rem;">
            <div class="col botlistbox">
                <form method="post" id="botIpsForm">
                    <label>
                        Bot IPs (format: <b>IP;Provider</b> per line):<br>
                        <textarea name="bot_ips" id="botIpsBox" style="height:140px"><?= $botIpsText ?></textarea>
                    </label>
                    <div class="botlinks">
                        <button name="save_bot_ips" value="1">Save Bot IPs</button>
                        <button type="button" id="downloadBotIps">Download Latest Bot IPs</button>
                        <a id="downloadBotIpsLocal" href="#" download="bot_ips.txt">Download Current</a>
                        <span id="downloadStatus" style="font-size:0.95em;color:#2851a3;"></span>
                    </div>
                </form>
            </div>
            <div class="col botlistbox">
                <form method="post">
                    <label>Bot CIDRs (CIDR per line):<br>
                        <textarea name="bot_cidrs" style="height:140px" id="botCidrsBox"><?= $botCidrsText ?></textarea>
                    </label>
                    <div class="botlinks">
                        <button name="save_bot_cidrs" value="1">Save Bot CIDRs</button>
                        <a id="downloadBotCidrsLocal" href="#" download="bot_cidrs.txt">Download Current</a>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div style="margin-top:2.5rem;">
        <h3 style="margin-bottom:0.5rem;">Logs</h3>
        <div class="log-controls">
            <button type="button" id="refreshBtn" style="background:#3bc57e;">Manual Refresh</button>
            <button type="button" id="toggleAuto" style="background:#ffc107;color:#222;">Auto Refresh: <span id="autoStatus">On</span></button>
            <form method="post" onsubmit="return confirm('Clear all logs?');" style="display:inline;">
                <input type="hidden" name="clear_logs" value="1">
                <button style="background:#e55353;margin-left:10px;">Clear Logs</button>
            </form>
        </div>
        <pre class="logsbox" id="logsbox">Loading logs...</pre>
    </div>
</div>
<div class="footer">
    By <a href="https://shellpuppy.com" target="_blank" style="color:inherit;text-decoration:underline;">ShellPuppy.com</a>. MIT License.
</div>
<script>
    // Logs auto-refresh
    let auto = true;
    let logsbox = document.getElementById('logsbox');
    let autoBtn = document.getElementById('toggleAuto');
    let refreshBtn = document.getElementById('refreshBtn');
    let interval = null;

    function fetchLogs() {
        fetch('?ajax=log')
            .then(r => r.text())
            .then(txt => { logsbox.textContent = txt; });
    }
    function setAuto(val) {
        auto = val;
        document.getElementById('autoStatus').textContent = auto ? "On" : "Off";
        if (auto && !interval) {
            interval = setInterval(fetchLogs, 5000);
        } else if (!auto && interval) {
            clearInterval(interval);
            interval = null;
        }
    }
    refreshBtn.onclick = fetchLogs;
    autoBtn.onclick = function() { setAuto(!auto); };
    fetchLogs();
    setAuto(true);
    setInterval(() => { if (auto && logsbox) logsbox.scrollTop = logsbox.scrollHeight; }, 600);

    // Download latest bot IPs from external source and update textarea (and file via PHP)
    document.getElementById('downloadBotIps').onclick = function(e) {
        e.preventDefault();
        const status = document.getElementById('downloadStatus');
        status.textContent = "Downloading...";
        fetch('download_bot_ips.php', {
            method: 'POST',
            headers: {'Content-Type':'application/x-www-form-urlencoded'},
            body: 'action=download'
        })
        .then(resp => resp.json())
        .then(data => {
            if(data.success) {
                document.getElementById('botIpsBox').value = data.content;
                status.textContent = "Latest list downloaded & saved!";
            } else {
                status.textContent = "Error: " + data.error;
            }
        }).catch(err => {
            status.textContent = "Fetch error.";
        });
    };

    // Download bot_ips.txt as a file (from current textarea)
    document.getElementById('downloadBotIpsLocal').onclick = function(e) {
        const data = document.getElementById('botIpsBox').value;
        const blob = new Blob([data], {type: "text/plain"});
        const url = URL.createObjectURL(blob);
        this.href = url;
        setTimeout(() => { URL.revokeObjectURL(url); }, 2000);
    };
    // Download bot_cidrs.txt as a file (from current textarea)
    document.getElementById('downloadBotCidrsLocal').onclick = function(e) {
        const data = document.getElementById('botCidrsBox').value;
        const blob = new Blob([data], {type: "text/plain"});
        const url = URL.createObjectURL(blob);
        this.href = url;
        setTimeout(() => { URL.revokeObjectURL(url); }, 2000);
    };
</script>
</body>
</html>
