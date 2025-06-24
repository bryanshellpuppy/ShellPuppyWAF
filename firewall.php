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

// ---- Helper: Check IP in CIDRs/IPs ----
function ip_in_cidrs($ip, $cidr_list) {
    foreach ($cidr_list as $cidr) {
        $cidr = trim($cidr);
        if ($cidr === '' || $cidr[0] === '#') continue;
        if (strpos($cidr, '/') === false) {
            if ($ip === $cidr) return true;
            continue;
        }
        list($subnet, $mask) = explode('/', $cidr, 2);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip_dec = ip2long($ip);
            $subnet_dec = ip2long($subnet);
            $mask_dec = ~((1 << (32 - (int)$mask)) - 1);
            if (($ip_dec & $mask_dec) === ($subnet_dec & $mask_dec)) return true;
        }
        // Optional: Add IPv6 support if desired.
    }
    return false;
}

class WAF {
    public static $config;
    public static $configPath = __DIR__ . '/config.json';
    public static $logPath = __DIR__ . '/logs/requests.log';

    public static function init() {
        self::loadConfig();

        // Whitelist check (CIDR/IP)
        if (ip_in_cidrs($_SERVER['REMOTE_ADDR'], self::$config['whitelisted_ips'] ?? [])) {
            return;
        }

        // 1. Check against known bot lists (CIDR and IP)
        self::checkBotLists();

        // 2. Random human verification
        self::randomHumanCheck();

        // 3. Standard WAF protections
        self::rateLimit();
        self::blockBadIPs();
        self::blockBadUserAgents();
        self::detectSQLInjection();
        self::detectXSS();
    }

    // ---- Bot IP and CIDR list check ----
    public static function checkBotLists() {
        // CIDR blocks from bot_cidrs.txt
        static $bot_cidrs = null;
        if ($bot_cidrs === null) {
            $bot_cidrs_file = __DIR__ . '/bot_cidrs.txt';
            $bot_cidrs = [];
            if (file_exists($bot_cidrs_file)) {
                $lines = file($bot_cidrs_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === '' || $line[0] === '#') continue;
                    $bot_cidrs[] = $line;
                }
            }
        }
        if (!empty($bot_cidrs) && ip_in_cidrs($_SERVER['REMOTE_ADDR'], $bot_cidrs)) {
            self::saveLog('Known Bot CIDR');
            self::deny('Your IP is associated with automated bots (CIDR).');
        }

        // Single IPs from bot_ips.txt (format: IP;Provider)
        static $bot_ips = null;
        if ($bot_ips === null) {
            $bot_ips_file = __DIR__ . '/bot_ips.txt';
            $bot_ips = [];
            if (file_exists($bot_ips_file)) {
                $lines = file($bot_ips_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === '' || $line[0] === '#') continue;
                    $parts = explode(';', $line, 2);
                    $ip = trim($parts[0]);
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $bot_ips[] = $ip;
                    }
                }
            }
        }
        if (!empty($bot_ips) && in_array($_SERVER['REMOTE_ADDR'], $bot_ips)) {
            self::saveLog('Known Bot IP');
            self::deny('Your IP is associated with automated bots (IP).');
        }
    }

    // ---- Random human verification (math challenge) ----
    public static function randomHumanCheck() {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        // If user has passed recently (set session for 1 hour), skip
        if (isset($_SESSION['waf_human_ok']) && $_SESSION['waf_human_ok'] > time()) {
            return;
        }
        // ~5% of requests (1 in 20) OR when submitting the challenge
        if (mt_rand(1, 20) === 1 || isset($_POST['waf_human_answer'])) {
            // Handle challenge POST
            if (isset($_POST['waf_human_answer'])) {
                if (isset($_SESSION['waf_human_sum']) && (int)$_POST['waf_human_answer'] === (int)$_SESSION['waf_human_sum']) {
                    $_SESSION['waf_human_ok'] = time() + 3600; // 1 hour pass
                    unset($_SESSION['waf_human_sum']);
                    header("Location: " . $_SERVER['REQUEST_URI']);
                    exit;
                } else {
                    $msg = "Incorrect. Please try again.";
                }
            } else {
                $msg = "";
            }
            // Generate a simple math challenge
            $a = rand(1, 9); $b = rand(1, 9);
            $_SESSION['waf_human_sum'] = $a + $b;
            echo "<!DOCTYPE html><html><head><title>Human Check</title>
                <style>body{font-family:sans-serif;background:#f7f9fa;display:flex;align-items:center;justify-content:center;height:100vh;}
                .box{background:#fff;padding:2rem 2.5rem;border-radius:12px;box-shadow:0 0 24px #0001;}
                input{font-size:1.2rem;padding:0.4rem 0.7rem;border-radius:6px;border:1px solid #ccc;}
                button{padding:0.5rem 1.4rem;font-size:1rem;background:#3887f6;color:white;border:none;border-radius:6px;cursor:pointer;}
                button:hover{background:#225bb0;}
                </style>
                </head><body><div class='box'>";
            echo "<h2>Please verify you're human</h2>";
            if (!empty($msg)) echo "<div style='color:red;margin-bottom:1em;'>$msg</div>";
            echo "<form method='post'>
                <label style='font-size:1.2em;'>
                    What is $a + $b? <input type='number' name='waf_human_answer' required autofocus>
                </label>
                <br><button>Verify</button>
            </form>";
            echo "<p style='font-size:0.9em;color:#888;margin-top:1em;'>Sorry, sometimes we need to check!</p>";
            echo "</div></body></html>";
            exit;
        }
    }

    // ---- Load config ----
    private static function loadConfig() {
        self::$config = json_decode(file_get_contents(self::$configPath), true);
    }

    // ---- Logging ----
    public static function saveLog($reason) {
        if (!is_dir(dirname(self::$logPath))) {
            mkdir(dirname(self::$logPath), 0777, true);
        }
        $entry = [
            'time' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'reason' => $reason
        ];
        file_put_contents(self::$logPath, json_encode($entry) . "\n", FILE_APPEND);
    }

    // ---- Blocked IPs (CIDR/IP) ----
    public static function blockBadIPs() {
        if (ip_in_cidrs($_SERVER['REMOTE_ADDR'], self::$config['blocked_ips'])) {
            self::saveLog('Blocked IP');
            self::deny('Blocked IP');
        }
    }

    // ---- Blocked User-Agents ----
    public static function blockBadUserAgents() {
        foreach (self::$config['blocked_agents'] as $agent) {
            if (stripos($_SERVER['HTTP_USER_AGENT'] ?? '', $agent) !== false) {
                self::saveLog('Blocked User-Agent');
                self::deny('Blocked User-Agent');
            }
        }
    }

    // ---- SQLi detection ----
    public static function detectSQLInjection() {
        foreach ($_REQUEST as $val) {
            foreach (self::$config['sql_patterns'] as $pattern) {
                if (stripos($val, $pattern) !== false) {
                    self::saveLog('Possible SQL Injection');
                    self::deny('SQL Injection');
                }
            }
        }
    }

    // ---- XSS detection ----
    public static function detectXSS() {
        foreach ($_REQUEST as $val) {
            foreach (self::$config['xss_patterns'] as $pattern) {
                if (stripos($val, $pattern) !== false) {
                    self::saveLog('Possible XSS');
                    self::deny('XSS Detected');
                }
            }
        }
    }

    // ---- Rate Limiting ----
    public static function rateLimit() {
        $ip = $_SERVER['REMOTE_ADDR'];
        $window = self::$config['rate_window_seconds'];
        $limit = self::$config['rate_limit'];

        $file = sys_get_temp_dir() . "/waf-{$ip}.rate";
        $hits = @file_get_contents($file);
        $hits = $hits ? json_decode($hits, true) : ['count' => 0, 'start' => time()];

        if (time() - $hits['start'] > $window) {
            $hits = ['count' => 1, 'start' => time()];
        } else {
            $hits['count']++;
        }

        file_put_contents($file, json_encode($hits));

        if ($hits['count'] > $limit) {
            self::saveLog('Rate Limit Exceeded');
            self::deny('Rate limit exceeded');
        }
    }

    // ---- Deny helper ----
    public static function deny($reason) {
        header('HTTP/1.1 403 Forbidden');
        $user_ip = htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Access Denied - Secure Information System</title>
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <style>
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: #f6f7fa;
                    margin: 0;
                }
                .gov-header {
                    background: #ffffff;
                    color: #000000;
                    padding: 24px 0 16px 0;
                    text-align: center;
                    border-bottom: 5px solid #e2ac13;
                }
                .gov-header h1 {
                    margin: 0 0 7px 0;
                    font-size: 2.2em;
                    letter-spacing: 2px;
		    color: #000000;
                }
                .gov-seal {
                    width: 65px;
                    height: 65px;
                                        background-size: contain;
                    margin: 0 auto 10px auto;
                }
                .container {
                    max-width: 560px;
                    margin: 40px auto;
                    background: #fff;
                    border: 1px solid #d9dbe1;
                    border-radius: 8px;
                    box-shadow: 0 2px 22px #12335a10;
                    padding: 36px 36px 30px 36px;
                    text-align: center;
                }
                .alert {
                    color: #b20a0a;
                    font-size: 1.4em;
                    margin: 12px 0 20px 0;
                    font-weight: bold;
                }
                .warning {
                    color: #e2ac13;
                    font-weight: bold;
                    margin-top: 16px;
                }
                .legal {
                    color: #1d2734;
                    margin-top: 16px;
                    font-size: 1.1em;
                }
                .small {
                    color: #788096;
                    margin-top: 32px;
                    font-size: 0.97em;
                }
                @media (max-width: 600px) {
                    .container {padding: 20px;}
                }
            </style>
        </head>
        <body>
            <div class="gov-header">
                <div class="gov-seal"></div>
		<img src="https://www.shellpuppy.com/color_logo2.png">
                <h1>Access Denied</h1>
                <div style="font-size:1.07em;">Secure Information System</div>
            </div>
            <div class="container">
                <div class="alert">
                    Your IP address (<b><?php echo $user_ip; ?></b>) has been banned from accessing this system.
                </div>
                <div>
                    <b>Reason:</b> <?php echo htmlspecialchars($reason); ?>
                    <br><br>
                    This is a restricted information system, provided for authorized use only.<br><br>
                    All activities on this system are actively monitored and recorded.<br>
                    Unauthorized access, attempted circumvention, or malicious activity is strictly prohibited.<br>
                </div>
                <div class="warning">
                    Violators will be prosecuted to the fullest extent of the law.
                </div>
                <div class="legal">
                    By accessing or using this system, you consent to monitoring and acknowledge that evidence of unauthorized use may be provided to law enforcement.
                </div>
                <div class="small">
                    If you believe this is an error, contact your system administrator.<br>
                    
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}
?>
