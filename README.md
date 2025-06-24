# ShellPuppyWAF
A PHP WAF written from a clean approach rather than using some of the older methods.
<br><br><img src=WAFshellpuppy.png>

# 🐾 ShellPuppy PHP Web Application Firewall (WAF)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> **ShellPuppy WAF** is a free, open-source PHP Web Application Firewall to help secure your web applications and APIs from common web threats, bots, abuse, and intrusion—easy to set up, highly configurable, and privacy-friendly.

---

## 🚀 Features

- **IP & CIDR Blocking**  
  Block malicious IP addresses and CIDR ranges with simple list management.

- **Bot Detection**  
  Automatic blocking based on downloadable bot IP lists and custom entries.

- **Whitelisting**  
  Allow trusted users and networks, bypassing WAF rules.

- **Rate Limiting**  
  Prevent brute force and scraping with customizable rate controls.

- **SQL Injection & XSS Protection**  
  Detect and block common SQLi and XSS patterns.

- **User-Agent Filtering**  
  Block unwanted crawlers and suspicious clients by User-Agent.

- **Randomized CAPTCHA Challenge**  
  Present human challenges randomly or on demand, with full admin control.

- **Modern Admin Panel**  
  - Live log viewing (with auto-refresh)
  - Configuration editor (patterns, limits, passwords)
  - Upload/download blocklists
  - One-click fetch of latest public bot lists
  - Secure login

- **Custom Banned IP Page**  
  Government-style template for legal and compliance notices.

- **Extensible**  
  Add your own rules, blocklists, and plugins easily.

---

## 🖥️ Screenshots

<p align="center">
  <img src="docs/screenshots/admin-panel.png" alt="Admin Panel" width="70%"/>
  <br>
  <em>Modern, responsive admin panel</em>
</p>

---

## ⚡ Quick Start

1. **Clone this repository**
   ```bash
   git clone https://github.com/shellpuppy/php-waf.git
   cd php-waf
