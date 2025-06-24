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
define('__ROOT__', dirname(dirname(__FILE__)));
require_once(__ROOT__.'/waf/firewall.php');
WAF::init();
?>
