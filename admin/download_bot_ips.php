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
$configPath = __DIR__ . '/../config.json';
$botIpsPath = __DIR__ . '/../bot_ips.txt';

// Secure: Only allow if admin is logged in
$config = json_decode(file_get_contents($configPath), true);
if (!isset($_SESSION['waf_admin'])) {
    echo json_encode(['success' => false, 'error' => 'Not authorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'download') {
    $url = "https://raw.githubusercontent.com/antoinevastel/avastel-bot-ips-lists/refs/heads/master/avastel-proxy-bot-ips-1day.txt";
    $data = @file_get_contents($url);
    if ($data !== false) {
        file_put_contents($botIpsPath, $data);
        echo json_encode(['success' => true, 'content' => $data]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to fetch list from GitHub']);
    }
    exit;
}
echo json_encode(['success' => false, 'error' => 'Invalid request']);
