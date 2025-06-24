# ShellPuppyWAF
A PHP WAF written from a clean approach rather than using some of the older methods.
<br><br><img src=WAFshellpuppy.png>

Copy sorce down to your php allication directory.
Take note of the log directory that needs to be writable.

Add the following to your header on pages you want to run the waf code.

<?php
define('__ROOT__', dirname(dirname(__FILE__)));
require_once(__ROOT__.'/waf/firewall.php');
WAF::init();
?>

You may need to adjust the include directory depending on what your server supports.
