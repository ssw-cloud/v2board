<?php

namespace App\Utils;
use App\Models\User;
use Illuminate\Support\Facades\Cache;

class Helper
{
    private const ED25519_ORDER_HEX = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';

    public static function uuidToBase64($uuid, $length)
    {
        return base64_encode(substr($uuid, 0, $length));
    }

    public static function getServerKey($timestamp, $length)
    {
        return base64_encode(substr(md5($timestamp), 0, $length));
    }

    public static function getShadowsocks2022KeyLength($cipher)
    {
        switch ($cipher) {
            case '2022-blake3-aes-128-gcm':
                return 16;
            case '2022-blake3-aes-256-gcm':
            case '2022-blake3-chacha20-poly1305':
                return 32;
            default:
                return 0;
        }
    }

    public static function buildShadowsocksPassword($uuid, $server)
    {
        $cipher = $server['cipher'] ?? '';
        $length = self::getShadowsocks2022KeyLength($cipher);
        if (!$length) {
            return $uuid;
        }
        return self::getServerKey($server['created_at'], $length) . ':' . self::uuidToBase64($uuid, $length);
    }

    public static function guid($format = false)
    {
        if (function_exists('com_create_guid') === true) {
            return md5(trim(com_create_guid(), '{}'));
        }
        $data = openssl_random_pseudo_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
        if ($format) {
            return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
        }
        return md5(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4)) . '-' . time());
    }

    public static function generateOrderNo(): string
    {
        $randomChar = mt_rand(10000, 99999);
        return date('YmdHms') . substr(microtime(), 2, 6) . $randomChar;
    }

    public static function exchange($from, $to)
    {
        $result = file_get_contents('https://api.exchangerate.host/latest?symbols=' . $to . '&base=' . $from);
        $result = json_decode($result, true);
        return $result['rates'][$to];
    }

    public static function randomChar($len, $special = false)
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        if ($special) {
            $chars .= '!@#$?|{/:%^&*()-_[]}<>=+,.';
        }
        
        $str = '';
        $max = strlen($chars) - 1;
        for ($i = 0; $i < $len; $i++) {
            $str .= $chars[random_int(0, $max)];
        }
        return $str;
    }

    public static function multiPasswordVerify($algo, $salt, $password, $hash)
    {
        switch($algo) {
            case 'md5': return md5($password) === $hash;
            case 'sha256': return hash('sha256', $password) === $hash;
            case 'md5salt': return md5($password . $salt) === $hash;
            default: return password_verify($password, $hash);
        }
    }

    public static function emailSuffixVerify($email, $suffixs)
    {
        $suffix = preg_split('/@/', $email)[1];
        if (!$suffix) return false;
        if (!is_array($suffixs)) {
            $suffixs = preg_split('/,/', $suffixs);
        }
        if (!in_array($suffix, $suffixs)) return false;
        return true;
    }

    public static function trafficConvert(int $byte)
    {
        $kb = 1024;
        $mb = 1048576;
        $gb = 1073741824;
        if ($byte > $gb) {
            return round($byte / $gb, 2) . ' GB';
        } else if ($byte > $mb) {
            return round($byte / $mb, 2) . ' MB';
        } else if ($byte > $kb) {
            return round($byte / $kb, 2) . ' KB';
        } else if ($byte < 0) {
            return 0;
        } else {
            return round($byte, 2) . ' B';
        }
    }

    public static function getSubscribeUrl($token)
    {
        $submethod = (int)config('v2board.show_subscribe_method', 0);
        $path = config('v2board.subscribe_path', '/api/v1/client/subscribe');
        if (empty($path)) {
            $path = '/api/v1/client/subscribe';
        } 
        $subscribeUrls = explode(',', config('v2board.subscribe_url'));
        $subscribeUrl = $subscribeUrls[rand(0, count($subscribeUrls) - 1)];
        switch ($submethod) {
            case 0:
                $path = "{$path}?token={$token}";
                if ($subscribeUrl) return $subscribeUrl . $path;
                return url($path);
                break;
            case 1:
                $newtoken = Cache::get("otp_{$token}");
                if (!$newtoken) {
                    $newtoken = self::base64EncodeUrlSafe(random_bytes(24));
                    $added = Cache::add("otp_{$token}", $newtoken, 86400);
                    if ($added) {
                        Cache::put("otpn_{$newtoken}", $token, 86400);
                    } else {
                        $newtoken = Cache::get("otp_{$token}");
                    }
                }
                $path = "{$path}?token={$newtoken}";
                if ($subscribeUrl) return $subscribeUrl . $path;
                return url($path);
                break;
            case 2:
                $timestep = (int)config('v2board.show_subscribe_expire', 5) * 60;
                $counter = floor(time() / $timestep);
                $counterBytes = pack('N*', 0) . pack('N*', $counter);
                $hash = hash_hmac('sha1', $counterBytes, $token, false);
                $user = User::where('token', $token)->select('id')->first();
                $newtoken = self::base64EncodeUrlSafe("{$user->id}:{$hash}");

                $path = "{$path}?token={$newtoken}";
                if ($subscribeUrl) return $subscribeUrl . $path;
                return url($path);
                break;
        }
    }

    public static function randomPort($range) {
        $portRange = explode('-', $range);
        return rand($portRange[0], $portRange[1]);
    }

    public static function base64EncodeUrlSafe($data)
    {
        $encoded = base64_encode($data);
        return str_replace(['+', '/', '='], ['-', '_', ''], $encoded);
    }

    public static function base64DecodeUrlSafe($data)
    {
        $b64 = str_replace(['-', '_'], ['+', '/'], $data);
        $pad = 4 - (strlen($b64) % 4);
        if ($pad < 4) {
            $b64 .= str_repeat('=', $pad);
        }
        return base64_decode($b64);
    }

    public static function encodeURIComponent($str) {
        $revert = array('%21'=>'!', '%2A'=>'*', '%27'=>"'", '%28'=>'(', '%29'=>')');
        return strtr(rawurlencode($str), $revert);
    }

    public static function buildUri($uuid, $server)
    {
        if ($server['type'] == 'v2node') {
            if (($server['protocol'] ?? null) === 'mieru') {
                return '';
            }
            $server['type'] = $server['protocol'];
        } 
        $method = "build" . ucfirst($server['type']) . "Uri";

        if (method_exists(self::class, $method)) {
            return self::$method($uuid, $server);
        }

        return '';
    }

    public static function buildUriString($scheme, $auth, $server, $name, $params = [])
    {
        $host = self::formatHost($server['host']);
        $port = $server['port'];
        $query = http_build_query($params);

        return "{$scheme}://{$auth}@{$host}:{$port}?{$query}#{$name}\r\n";
    }

    public static function buildSimpleUriString($scheme, $auth, $server, $name)
    {
        $host = self::formatHost($server['host']);
        $port = $server['port'];

        return "{$scheme}://{$auth}@{$host}:{$port}#{$name}\r\n";
    }

    public static function formatHost($host)
    {
        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[$host]" : $host;
    }

    public static function buildShadowsocksUri($uuid, $server)
    {
        $cipher = $server['cipher'];
        $password = self::buildShadowsocksPassword($uuid, $server);
        $name = rawurlencode($server['name']);
        $str = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode("{$cipher}:{$password}"));
        $add = self::formatHost($server['host']);
        $uri = "ss://{$str}@{$add}:{$server['port']}";
        if ($server['obfs'] == 'http') {
            $uri .= "?plugin=obfs-local;obfs=http;obfs-host={$server['obfs-host']};path={$server['obfs-path']}";
        } else if ((($server['network'] ?? null) == 'http') && isset($server['network_settings']['Host'])) {
            $path = $server['network_settings']['path'] ?? '/';
            $uri .= "?plugin=obfs-local;obfs=tls;obfs-host={$server['network_settings']['Host']};path={$path}";
        }
        return $uri."#{$name}\r\n";
    }

    public static function buildVmessUri($uuid, $server)
    {
        $config = [
            "v" => "2",
            "ps" => $server['name'],
            "add" => self::formatHost($server['host']),
            "port" => (string)$server['port'],
            "id" => $uuid,
            "aid" => '0',
            "scy" => 'auto',
            "net" => $server['network'],
            "type" => 'none',
            "host" => '',
            "path" => '',
            "tls" => $server['tls'] ? "tls" : "",
            "fp" => 'chrome',
        ];

        if ($server['tls']) {
            $tlsSettings = $server['tls_settings'] ?? $server['tlsSettings'] ?? [];
            $config['allowInsecure'] = (int)($tlsSettings['allow_insecure'] ?? $tlsSettings['allowInsecure'] ?? 0);
            $config['sni'] = $tlsSettings['server_name'] ?? $tlsSettings['serverName'] ?? '';
        }
        
        $network = (string)$server['network'];
        $networkSettings = $server['networkSettings'] ?? ($server['network_settings'] ?? []);
    
        switch ($network) {
            case 'tcp':
                if (!empty($networkSettings['header']['type']) && $networkSettings['header']['type'] === 'http') {
                    $config['type'] = $networkSettings['header']['type'];
                    $config['host'] = $networkSettings['header']['request']['headers']['Host'][0] ?? null;
                    $config['path'] = $networkSettings['header']['request']['path'][0] ?? null;
                }
                break;
    
            case 'ws':
                $config['path'] = $networkSettings['path'] ?? null;
                $config['host'] = $networkSettings['headers']['Host'] ?? null;
                isset($networkSettings['security']) && $config['scy'] = $networkSettings['security'];
                break;
    
            case 'grpc':
                $config['path'] = $networkSettings['serviceName'] ?? null;
                break;

            case 'kcp':
                if (isset($networkSettings['seed'])) {
                    $config['path'] = $networkSettings['seed'];
                }
                $config['type'] = $networkSettings['header']['type'] ?? 'none';
                break;

            case 'httpupgrade':
                $config['path'] = $networkSettings['path'] ?? null;
                $config['host'] = $networkSettings['host'] ?? null;
                break;
            
            case 'xhttp':
                $config['path'] = $networkSettings['path'] ?? null;
                $config['host'] = $networkSettings['host'] ?? null;
                $config['mode'] = $networkSettings['mode'] ?? 'auto';
                $config['extra'] = isset($networkSettings['extra']) ? json_encode($networkSettings['extra'], JSON_UNESCAPED_SLASHES) : null;
                break;
        }

        return "vmess://" . base64_encode(json_encode($config)) . "\r\n";
    }

    public static function buildVlessUri($uuid, $server)
    {
        $name = self::encodeURIComponent($server['name']);
        $tlsSettings = $server['tls_settings'] ?? [];

        $config = [
            "type" => $server['network'],
            "encryption" => "none",
            "host" => "",
            "path" => "",
            "headerType" => "none",
            "quicSecurity" => "none",
            "serviceName" => "",
            "security" => $server['tls'] != 0 ? ($server['tls'] == 2 ? "reality" : "tls") : "",
            "flow" => $server['flow'],
            "fp" => $tlsSettings['fingerprint'] ?? 'chrome',
            "insecure" => $tlsSettings['allow_insecure'] ?? 0,
        ];

        if ($server['tls']) {
            $tlsSettings = $server['tls_settings'] ?? [];
            $config['sni'] = $tlsSettings['server_name'] ?? '';
            if ($server['tls'] == 2) {
                $config['pbk'] = $tlsSettings['public_key'] ?? '';
                $config['sid'] = $tlsSettings['short_id'] ?? '';
            }
        }
        if (!empty($tlsSettings['ech'])) {
            if ($tlsSettings['ech'] === 'cloudflare') {
                $config['ech'] = 'cloudflare-ech.com+https://doh.pub/dns-query';
            } elseif ($tlsSettings['ech'] === 'custom' && !empty($tlsSettings['ech_config'])) {
                $config['ech'] = is_array($tlsSettings['ech_config']) ? $tlsSettings['ech_config'][0] : $tlsSettings['ech_config'];
            }
        }
        if (isset($server['encryption']) && $server['encryption'] == 'mlkem768x25519plus') {
            $encSettings = $server['encryption_settings'];
            $enc = 'mlkem768x25519plus.' . ($encSettings['mode'] ?? 'native') . '.' . ($encSettings['rtt'] ?? '1rtt');
            if (isset($encSettings['client_padding']) && !empty($encSettings['client_padding'])) {
                $enc .= '.' . $encSettings['client_padding'];
            }
            $enc .= '.' . ($encSettings['password'] ?? '');
            $config['encryption'] = $enc;
        }

        self::configureNetworkSettings($server, $config);

        return self::buildUriString('vless', $uuid, $server, $name, $config);
    }

    public static function buildTrojanUri($password, $server)
    {
        $tlsSettings = $server['tls_settings'] ?? [];
        $config = [
            'allowInsecure' => $server['allow_insecure'] ?? ($tlsSettings['allow_insecure'] ?? 0),
            'peer' => $server['server_name'] ?? ($tlsSettings['server_name'] ?? ''),
            'sni' => $server['server_name'] ?? ($tlsSettings['server_name'] ?? ''),
            'type'=> $server['network'],
        ];

        if(isset($server['network']) && in_array($server['network'], ["grpc", "ws"])){
            if($server['network'] === "grpc" && isset($server['network_settings']['serviceName'])) {
                $config['serviceName'] = $server['network_settings']['serviceName'];
            }
            if($server['network'] === "ws") {
                if(isset($server['network_settings']['path'])) {
                    $config['path'] = $server['network_settings']['path'];
                }
                if(isset($server['network_settings']['headers']['Host'])) {
                    $config['host'] = $server['network_settings']['headers']['Host'];
                }
            }
        }
        if (!empty($tlsSettings['ech'])) {
            if ($tlsSettings['ech'] === 'cloudflare') {
                $config['ech'] = 'cloudflare-ech.com+https://doh.pub/dns-query';
            } elseif ($tlsSettings['ech'] === 'custom' && !empty($tlsSettings['ech_config'])) {
                $config['ech'] = is_array($tlsSettings['ech_config']) ? $tlsSettings['ech_config'][0] : $tlsSettings['ech_config'];
            }
        }
        $query = http_build_query($config);
        return "trojan://{$password}@" . self::formatHost($server['host']) . ":{$server['port']}?{$query}#". rawurlencode($server['name']) . "\r\n";
    }

    public static function buildHysteriaUri($password, $server)
    {
        $remote = self::formatHost($server['host']);
        $name = self::encodeURIComponent($server['name']);

        $parts = explode(",", $server['port']);
        $firstPort = strpos($parts[0], '-') !== false ? explode('-', $parts[0])[0] : $parts[0];

        $uri = $server['version'] == 2 ?
            "hysteria2://{$password}@{$remote}:{$firstPort}/?insecure={$server['insecure']}&sni={$server['server_name']}" :
            "hysteria://{$remote}:{$firstPort}/?protocol=udp&auth={$password}&insecure={$server['insecure']}&peer={$server['server_name']}&upmbps={$server['down_mbps']}&downmbps={$server['up_mbps']}";

        if (isset($server['obfs']) && isset($server['obfs_password'])) {
            $obfs_password = rawurlencode($server['obfs_password']);
            $uri .= $server['version'] == 2 ? 
                "&obfs={$server['obfs']}&obfs-password={$obfs_password}" :
                "&obfs={$server['obfs']}&obfsParam{$obfs_password}";
        }
        if (count($parts) !== 1 || strpos($parts[0], '-') !== false) {
            $uri .= "&mport={$server['mport']}";
        }
        return "{$uri}#{$name}\r\n";
    }

    public static function buildHysteria2Uri($password, $server)
    {
        $remote = self::formatHost($server['host']);
        $name = self::encodeURIComponent($server['name']);

        $parts = explode(",", $server['port']);
        $firstPort = strpos($parts[0], '-') !== false ? explode('-', $parts[0])[0] : $parts[0];
        $tlsSettings = $server['tls_settings'] ?? [];
        $insecure = $tlsSettings['allow_insecure'] ?? 0;
        $sni = $tlsSettings['server_name'] ?? '';
        $uri = "hysteria2://{$password}@{$remote}:{$firstPort}/?insecure={$insecure}&sni={$sni}";

        if (isset($server['obfs']) && isset($server['obfs_password'])) {
            $obfs_password = rawurlencode($server['obfs_password']);
            $uri .= "&obfs={$server['obfs']}&obfs-password={$obfs_password}";
        }
        if (count($parts) !== 1 || strpos($parts[0], '-') !== false) {
            $uri .= "&mport={$server['mport']}";
        }
        return "{$uri}#{$name}\r\n";
    }

    public static function buildTuicUri($password, $server)
    {
        $tlsSettings = $server['tls_settings'] ?? [];
        $config = [
            'sni' => $server['server_name'] ?? ($tlsSettings['server_name'] ?? ''),
            'alpn'=> 'h3',
            'congestion_control' => $server['congestion_control'],
            'allow_insecure' => $server['insecure'] ?? ($tlsSettings['allow_insecure'] ?? 0),
            'disable_sni' => $server['disable_sni'],
            'udp_relay_mode' => $server['udp_relay_mode'],
        ];

        $remote = self::formatHost($server['host']);
        $port = $server['port'];
        $name = self::encodeURIComponent($server['name']);

        $query = http_build_query($config);
        return "tuic://{$password}:{$password}@{$remote}:{$port}?{$query}#{$name}\r\n";
    }

    public static function buildAnytlsUri($password, $server)
    {
        $tlsSettings = $server['tls_settings'] ?? [];
        $config = [
            'type' => $server['network'] ?? 'tcp',
            'insecure' => $server['insecure'] ?? ($tlsSettings['allow_insecure'] ?? 0),
            'fp' => $tlsSettings['fingerprint'] ?? 'chrome',
        ];
        if (isset($server['server_name']) || isset($tlsSettings['server_name'])) {
            $config['sni'] = $server['server_name'] ?? ($tlsSettings['server_name'] ?? '');
        }
        if (isset($server['tls']) && $server['tls'] == 2) {
            $config['security'] = 'reality';
            $config['pbk'] = $tlsSettings['public_key'] ?? '';
            $config['sid'] = $tlsSettings['short_id'] ?? '';
        }
        $remote = self::formatHost($server['host']);
        $port = $server['port'];
        $name = self::encodeURIComponent($server['name']);
        if (isset($server['network']) && isset($server['network_settings'])) {
            self::configureNetworkSettings($server, $config);
        }
        $query = http_build_query($config);
        return "anytls://{$password}@{$remote}:{$port}/?{$query}#{$name}\r\n";
    }

    public static function buildNaiveUri($uuid, $server)
    {
        return self::buildNaiveV2rayNUri($uuid, $server);
    }

    public static function buildMieruUri($uuid, $server)
    {
        $host = self::formatHost($server['host']);
        $name = self::encodeURIComponent($server['name']);
        $profile = $server['name'];
        $ports = [];
        $portValue = (string)($server['mport'] ?? $server['port']);
        foreach (explode(',', $portValue) as $port) {
            $port = trim($port);
            if ($port !== '') {
                $ports[] = $port;
            }
        }
        if (empty($ports)) {
            $ports[] = (string)$server['port'];
        }

        $params = [
            'profile' => $profile,
            'mtu' => 1400,
            'handshake-mode' => 'HANDSHAKE_STANDARD',
            'multiplexing' => 'MULTIPLEXING_LOW',
        ];
        $transport = strtoupper($server['network'] ?? 'tcp');
        if (!in_array($transport, ['TCP', 'UDP'])) {
            $transport = 'TCP';
        }
        foreach ($ports as $port) {
            $params[] = ['port', $port];
            $params[] = ['protocol', $transport];
        }

        $queryParts = [];
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                $queryParts[] = rawurlencode($value[0]) . '=' . rawurlencode($value[1]);
            } else {
                $queryParts[] = rawurlencode($key) . '=' . rawurlencode($value);
            }
        }
        $query = implode('&', $queryParts);
        $auth = rawurlencode($uuid) . ':' . rawurlencode($uuid);
        return "mierus://{$auth}@{$host}?{$query}#{$name}\r\n";
    }

    public static function buildShadowtlsUri($uuid, $server)
    {
        $cipher = !empty($server['cipher']) ? $server['cipher'] : '2022-blake3-aes-128-gcm';
        $server['cipher'] = $cipher;
        $password = self::buildShadowsocksPassword($uuid, $server);
        $host = self::formatHost($server['host']);
        $name = rawurlencode($server['name']);
        $userinfo = self::base64EncodeUrlSafe("{$cipher}:{$password}@{$host}:{$server['port']}");
        $shadowTls = self::base64EncodeUrlSafe(json_encode([
            'version' => '3',
            'host' => self::getShadowtlsSni($server),
            'password' => $password
        ], JSON_UNESCAPED_SLASHES));

        return "ss://{$userinfo}?shadow-tls={$shadowTls}#{$name}\r\n";
    }

    public static function buildShadowtlsClashProxy($uuid, $server)
    {
        $cipher = !empty($server['cipher']) ? $server['cipher'] : '2022-blake3-aes-128-gcm';
        $server['cipher'] = $cipher;
        $password = self::buildShadowsocksPassword($uuid, $server);
        return [
            'name' => $server['name'],
            'type' => 'ss',
            'server' => $server['host'],
            'port' => (int)$server['port'],
            'cipher' => $cipher,
            'password' => $password,
            'udp' => true,
            'plugin' => 'shadow-tls',
            'plugin-opts' => [
                'host' => self::getShadowtlsSni($server),
                'password' => $password,
                'version' => 3,
            ],
        ];
    }

    public static function buildNekoboxShadowtlsUri($uuid, $server)
    {
        $payload = self::encodeNekoboxShadowtlsBean($uuid, $server);
        return "sn://null?{$payload}\r\n";
    }

    public static function getShadowtlsSni($server)
    {
        $tlsSettings = $server['tls_settings'] ?? [];
        return $tlsSettings['server_name'] ?? $tlsSettings['serverName'] ?? $server['host'];
    }

    private static function encodeNekoboxShadowtlsBean($uuid, $server)
    {
        $cipher = !empty($server['cipher']) ? $server['cipher'] : '2022-blake3-aes-128-gcm';
        $server['cipher'] = $cipher;
        $password = self::buildShadowsocksPassword($uuid, $server);
        $tlsSettings = $server['tls_settings'] ?? [];
        $bytes = '';
        $bytes .= self::kryoWriteInt(0);
        $bytes .= self::kryoWriteInt(4);
        $bytes .= self::kryoWriteString($server['host']);
        $bytes .= self::kryoWriteInt((int)$server['port']);
        $bytes .= self::kryoWriteString('');
        $bytes .= self::kryoWriteString(null);
        $bytes .= self::kryoWriteString('tcp');
        $bytes .= self::kryoWriteString('tls');
        $bytes .= self::kryoWriteString(self::getShadowtlsSni($server));
        $bytes .= self::kryoWriteString('');
        $bytes .= self::kryoWriteString('');
        $bytes .= self::kryoWriteBoolean(($tlsSettings['allow_insecure'] ?? 0) == 1);
        $bytes .= self::kryoWriteString('');
        $bytes .= self::kryoWriteString('');
        $bytes .= self::kryoWriteString('');
        $bytes .= self::kryoWriteBoolean(false);
        $bytes .= self::kryoWriteString('');
        $bytes .= self::kryoWriteInt(0);
        $bytes .= self::kryoWriteBoolean(false);
        $bytes .= self::kryoWriteBoolean(false);
        $bytes .= self::kryoWriteInt(0);
        $bytes .= self::kryoWriteInt(1);
        $bytes .= self::kryoWriteInt(3);
        $bytes .= self::kryoWriteString($password);
        $bytes .= self::kryoWriteInt(1);
        $bytes .= self::kryoWriteString($server['name']);
        $bytes .= self::kryoWriteString('');
        $bytes .= self::kryoWriteString('');

        return self::base64EncodeUrlSafe(gzcompress($bytes, 9));
    }

    private static function kryoWriteInt($value)
    {
        return pack('V', (int)$value);
    }

    private static function kryoWriteBoolean($value)
    {
        return chr($value ? 1 : 0);
    }

    private static function kryoWriteString($value)
    {
        if ($value === null) {
            return chr(0x80);
        }
        if ($value === '') {
            return chr(0x81);
        }

        if (preg_match('/^[\x00-\x7F]{2,32}$/', $value)) {
            $bytes = $value;
            $last = strlen($bytes) - 1;
            return substr($bytes, 0, $last) . chr(ord($bytes[$last]) | 0x80);
        }

        $length = self::utf16Length($value) + 1;
        return self::kryoWriteVarIntFlag(true, $length) . $value;
    }

    private static function kryoWriteVarIntFlag($flag, $value)
    {
        $value = (int)$value;
        $first = ($value & 0x3f) | ($flag ? 0x80 : 0);
        $value >>= 6;
        if ($value === 0) {
            return chr($first);
        }

        $bytes = chr($first | 0x40);
        while ($value >= 0x80) {
            $bytes .= chr(($value & 0x7f) | 0x80);
            $value >>= 7;
        }
        return $bytes . chr($value);
    }

    private static function utf16Length($value)
    {
        if (function_exists('mb_convert_encoding')) {
            return (int)(strlen(mb_convert_encoding($value, 'UTF-16LE', 'UTF-8')) / 2);
        }

        preg_match_all('/./us', $value, $matches);
        $length = 0;
        foreach ($matches[0] as $char) {
            $code = self::utf8Codepoint($char);
            $length += $code > 0xffff ? 2 : 1;
        }
        return $length;
    }

    private static function utf8Codepoint($char)
    {
        $bytes = array_values(unpack('C*', $char));
        $first = $bytes[0];
        if ($first < 0x80) return $first;
        if ($first < 0xe0) return (($first & 0x1f) << 6) | ($bytes[1] & 0x3f);
        if ($first < 0xf0) return (($first & 0x0f) << 12) | (($bytes[1] & 0x3f) << 6) | ($bytes[2] & 0x3f);
        return (($first & 0x07) << 18) | (($bytes[1] & 0x3f) << 12) | (($bytes[2] & 0x3f) << 6) | ($bytes[3] & 0x3f);
    }

    public static function normalizeSudokuSettings($settings, $generateMissingKey = false)
    {
        $settings = is_array($settings) ? $settings : [];
        $httpmaskInput = isset($settings['httpmask']) && is_array($settings['httpmask']) ? $settings['httpmask'] : [];

        $privateKey = strtolower(trim((string)($settings['master_private_key'] ?? '')));
        $publicKey = strtolower(trim((string)($settings['master_public_key'] ?? '')));
        if ($generateMissingKey && $privateKey === '') {
            $pair = self::generateSudokuMasterKeyPair();
            $privateKey = $pair['master_private_key'];
            $publicKey = $pair['master_public_key'];
        }
        if ($publicKey === '' && $privateKey !== '') {
            $publicKey = self::recoverSudokuPublicKey($privateKey);
        }

        $paddingMin = (int)($settings['padding_min'] ?? $settings['padding-min'] ?? 5);
        $paddingMax = (int)($settings['padding_max'] ?? $settings['padding-max'] ?? 15);
        if ($paddingMin < 0) $paddingMin = 0;
        if ($paddingMax < $paddingMin) $paddingMax = $paddingMin;

        $maskHost = trim((string)($httpmaskInput['mask_host'] ?? $httpmaskInput['mask-host'] ?? $httpmaskInput['host'] ?? ''));
        $pathRoot = trim((string)($httpmaskInput['path_root'] ?? $httpmaskInput['path-root'] ?? ''));
        $httpmask = [
            'disable' => self::normalizeBool($httpmaskInput['disable'] ?? true, true),
            'mode' => self::normalizeSudokuChoice($httpmaskInput['mode'] ?? 'legacy', ['legacy', 'stream', 'poll', 'auto', 'ws'], 'legacy'),
            'tls' => self::normalizeBool($httpmaskInput['tls'] ?? false, false),
            'host' => $maskHost,
            'mask_host' => $maskHost,
            'path_root' => $pathRoot,
            'multiplex' => self::normalizeSudokuChoice($httpmaskInput['multiplex'] ?? ($settings['multiplex'] ?? 'off'), ['off', 'auto', 'on'], 'off'),
        ];

        return [
            'master_private_key' => $privateKey,
            'master_public_key' => $publicKey,
            'aead_method' => self::normalizeSudokuChoice($settings['aead_method'] ?? $settings['aead-method'] ?? $settings['aead'] ?? 'chacha20-poly1305', ['chacha20-poly1305', 'aes-128-gcm', 'none'], 'chacha20-poly1305'),
            'table_type' => self::normalizeSudokuTableType($settings['table_type'] ?? $settings['table-type'] ?? $settings['ascii'] ?? 'prefer_entropy'),
            'padding_min' => $paddingMin,
            'padding_max' => $paddingMax,
            'custom_table' => strtolower(trim((string)($settings['custom_table'] ?? $settings['custom-table'] ?? ''))),
            'custom_tables' => self::normalizeSudokuStringList($settings['custom_tables'] ?? $settings['custom-tables'] ?? []),
            'enable_pure_downlink' => self::normalizeBool($settings['enable_pure_downlink'] ?? $settings['enable-pure-downlink'] ?? true, true),
            'suspicious_action' => self::normalizeSudokuChoice($settings['suspicious_action'] ?? 'silent', ['silent', 'fallback'], 'silent'),
            'fallback_address' => trim((string)($settings['fallback_address'] ?? '')),
            'httpmask' => $httpmask,
            'multiplex' => $httpmask['multiplex'],
        ];
    }

    public static function generateSudokuMasterKeyPair()
    {
        $privateKey = self::generateSudokuScalar();
        $publicKey = self::ed25519BaseNoClamp($privateKey);
        return [
            'master_private_key' => bin2hex($privateKey),
            'master_public_key' => $publicKey === null ? '' : bin2hex($publicKey),
        ];
    }

    public static function recoverSudokuPublicKey($privateKey)
    {
        $raw = @hex2bin(trim((string)$privateKey));
        if ($raw === false) return '';
        if (strlen($raw) === 64) {
            $raw = self::sudokuScalarAdd(substr($raw, 0, 32), substr($raw, 32, 32));
        } elseif (strlen($raw) !== 32) {
            return '';
        }
        $publicKey = self::ed25519BaseNoClamp($raw);
        return $publicKey === null ? '' : bin2hex($publicKey);
    }

    public static function buildSudokuClientKey($uuid, $server, $userId = null)
    {
        $settings = self::normalizeSudokuSettings($server['encryption_settings'] ?? []);
        $masterHex = strtolower(trim((string)($settings['master_private_key'] ?? '')));
        if (!preg_match('/^[0-9a-f]{64}$/', $masterHex)) {
            return '';
        }
        if ($userId === null || $userId === '') {
            $userId = User::where('uuid', $uuid)->value('id');
        }
        if ($userId === null || $userId === '') {
            return '';
        }
        $nodeId = (int)($server['id'] ?? 0);
        $seed = sprintf('v2sudoku|node:%d|uid:%d|uuid:%s|master:%s', $nodeId, (int)$userId, $uuid, $masterHex);
        $r = self::sudokuScalarReduce(hash('sha512', $seed, true));
        $k = self::sudokuScalarSub(hex2bin($masterHex), $r);
        $clientKey = bin2hex($r . $k);

        if (!empty($settings['master_public_key'])) {
            $recovered = self::recoverSudokuPublicKey($clientKey);
            if ($recovered !== '' && strtolower($settings['master_public_key']) !== $recovered) {
                return '';
            }
        }

        return $clientKey;
    }

    public static function buildSudokuClashProxy($user, $server)
    {
        $uuid = self::getSudokuUserValue($user, 'uuid');
        if ($uuid === null || $uuid === '') {
            $uuid = is_scalar($user) ? (string)$user : '';
        }
        $userId = self::getSudokuUserValue($user, 'id');
        $key = self::buildSudokuClientKey($uuid, $server, $userId);
        if ($key === '') {
            return null;
        }

        $settings = self::normalizeSudokuSettings($server['encryption_settings'] ?? []);
        $httpmask = $settings['httpmask'];
        $array = [
            'name' => $server['name'],
            'type' => 'sudoku',
            'server' => $server['host'],
            'port' => (int)$server['port'],
            'key' => $key,
            'aead-method' => $settings['aead_method'],
            'padding-min' => (int)$settings['padding_min'],
            'padding-max' => (int)$settings['padding_max'],
            'table-type' => $settings['table_type'],
            'httpmask' => [
                'disable' => (bool)$httpmask['disable'],
                'mode' => $httpmask['mode'],
                'tls' => (bool)$httpmask['tls'],
                'host' => $httpmask['host'],
                'path-root' => $httpmask['path_root'],
                'multiplex' => $httpmask['multiplex'],
            ],
            'enable-pure-downlink' => (bool)$settings['enable_pure_downlink'],
        ];
        if ($settings['custom_table'] !== '') {
            $array['custom-table'] = $settings['custom_table'];
        }
        if (!empty($settings['custom_tables'])) {
            $array['custom-tables'] = $settings['custom_tables'];
        }
        return $array;
    }

    private static function getSudokuUserValue($user, $key)
    {
        if (is_array($user)) {
            return $user[$key] ?? null;
        }
        if ($user instanceof \ArrayAccess && isset($user[$key])) {
            return $user[$key];
        }
        if (is_object($user)) {
            if (isset($user->{$key})) {
                return $user->{$key};
            }
            if (method_exists($user, 'getAttribute')) {
                return $user->getAttribute($key);
            }
        }
        return null;
    }

    public static function buildSudokuUri($uuid, $server)
    {
        $key = self::buildSudokuClientKey($uuid, $server);
        if ($key === '') {
            return '';
        }

        $settings = self::normalizeSudokuSettings($server['encryption_settings'] ?? []);
        $httpmask = $settings['httpmask'];
        $payload = [
            'h' => $server['host'],
            'p' => (int)$server['port'],
            'k' => $key,
            'a' => self::encodeSudokuAscii($settings['table_type']),
            'e' => $settings['aead_method'],
            'm' => 1080,
            'hd' => (bool)$httpmask['disable'],
        ];
        if (!$settings['enable_pure_downlink']) {
            $payload['x'] = true;
        }
        if ($settings['custom_table'] !== '') {
            $payload['t'] = $settings['custom_table'];
        }
        if (!empty($settings['custom_tables'])) {
            $payload['ts'] = $settings['custom_tables'];
        }
        if ($httpmask['mode'] !== 'legacy') {
            $payload['hm'] = $httpmask['mode'];
        }
        if ($httpmask['tls']) {
            $payload['ht'] = true;
        }
        if ($httpmask['mask_host'] !== '') {
            $payload['hh'] = $httpmask['mask_host'];
        }
        if ($httpmask['multiplex'] !== 'off') {
            $payload['hx'] = $httpmask['multiplex'];
        }
        if ($httpmask['path_root'] !== '') {
            $payload['hy'] = $httpmask['path_root'];
        }

        $encoded = rtrim(strtr(base64_encode(json_encode($payload, JSON_UNESCAPED_SLASHES)), '+/', '-_'), '=');
        return "sudoku://{$encoded}#" . self::encodeURIComponent($server['name']) . "\r\n";
    }

    private static function normalizeBool($value, $default = false)
    {
        if ($value === null || $value === '') return $default;
        if (is_bool($value)) return $value;
        if (is_numeric($value)) return ((int)$value) !== 0;
        $parsed = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        return $parsed === null ? $default : $parsed;
    }

    private static function normalizeSudokuChoice($value, $allowed, $default)
    {
        $value = strtolower(trim((string)$value));
        return in_array($value, $allowed, true) ? $value : $default;
    }

    private static function normalizeSudokuTableType($value)
    {
        $value = strtolower(trim((string)$value));
        switch ($value) {
            case 'ascii':
                return 'prefer_ascii';
            case 'entropy':
                return 'prefer_entropy';
            case 'prefer_ascii':
            case 'prefer_entropy':
            case 'up_ascii_down_entropy':
            case 'up_entropy_down_ascii':
                return $value;
            default:
                return 'prefer_entropy';
        }
    }

    private static function normalizeSudokuStringList($value)
    {
        if (is_string($value)) {
            $value = preg_split('/[\r\n,]+/', $value);
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            $item = strtolower(trim((string)$item));
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return array_values(array_unique($out));
    }

    private static function encodeSudokuAscii($value)
    {
        switch (self::normalizeSudokuTableType($value)) {
            case 'prefer_ascii':
                return 'ascii';
            case 'prefer_entropy':
                return 'entropy';
            default:
                return self::normalizeSudokuTableType($value);
        }
    }

    private static function generateSudokuScalar()
    {
        do {
            $scalar = self::sudokuScalarReduce(random_bytes(64));
        } while (trim($scalar, "\0") === '');
        return $scalar;
    }

    private static function sudokuScalarReduce($input)
    {
        $input = str_pad(substr($input, 0, 64), 64, "\0");
        $native = self::callSodium('sodium_crypto_core_ed25519_scalar_reduce', 'crypto_core_ed25519_scalar_reduce', [$input]);
        if ($native !== null) {
            return $native;
        }
        return self::modLittleEndian($input);
    }

    private static function sudokuScalarSub($a, $b)
    {
        $native = self::callSodium('sodium_crypto_core_ed25519_scalar_sub', 'crypto_core_ed25519_scalar_sub', [$a, $b]);
        if ($native !== null) {
            return $native;
        }
        $aBE = strrev($a);
        $bBE = strrev($b);
        $order = hex2bin(self::ED25519_ORDER_HEX);
        if (self::binaryCompareBE($aBE, $bBE) >= 0) {
            return strrev(self::fixedBE(self::binarySubBE($aBE, $bBE), 32));
        }
        $sum = self::binaryAddBE($aBE, $order);
        return strrev(self::fixedBE(self::binarySubBE($sum, $bBE), 32));
    }

    private static function sudokuScalarAdd($a, $b)
    {
        $native = self::callSodium('sodium_crypto_core_ed25519_scalar_add', 'crypto_core_ed25519_scalar_add', [$a, $b]);
        if ($native !== null) {
            return $native;
        }
        $order = hex2bin(self::ED25519_ORDER_HEX);
        $sum = self::binaryAddBE(strrev($a), strrev($b));
        if (self::binaryCompareBE($sum, $order) >= 0) {
            $sum = self::binarySubBE($sum, $order);
        }
        return strrev(self::fixedBE($sum, 32));
    }

    private static function ed25519BaseNoClamp($scalar)
    {
        try {
            $native = self::callSodium('sodium_crypto_scalarmult_ed25519_base_noclamp', 'crypto_scalarmult_ed25519_base_noclamp', [$scalar]);
            return $native === null ? null : $native;
        } catch (\Throwable $e) {
            return null;
        }
    }

    private static function callSodium($function, $compatMethod, $args)
    {
        if (function_exists($function)) {
            return $function(...$args);
        }
        if (class_exists('\\ParagonIE_Sodium_Compat') && is_callable(['\\ParagonIE_Sodium_Compat', $compatMethod])) {
            return call_user_func_array(['\\ParagonIE_Sodium_Compat', $compatMethod], $args);
        }
        return null;
    }

    private static function modLittleEndian($littleEndian)
    {
        $order = hex2bin(self::ED25519_ORDER_HEX);
        $bytes = strrev($littleEndian);
        $remainder = "\0";
        for ($i = 0, $len = strlen($bytes); $i < $len; $i++) {
            $remainder = self::trimBE($remainder . $bytes[$i]);
            while (self::binaryCompareBE($remainder, $order) >= 0) {
                $remainder = self::binarySubBE($remainder, $order);
            }
        }
        return strrev(self::fixedBE($remainder, 32));
    }

    private static function trimBE($value)
    {
        $value = ltrim($value, "\0");
        return $value === '' ? "\0" : $value;
    }

    private static function fixedBE($value, $length)
    {
        $value = self::trimBE($value);
        if (strlen($value) > $length) {
            $value = substr($value, -$length);
        }
        return str_pad($value, $length, "\0", STR_PAD_LEFT);
    }

    private static function binaryCompareBE($a, $b)
    {
        $a = self::trimBE($a);
        $b = self::trimBE($b);
        if (strlen($a) !== strlen($b)) {
            return strlen($a) < strlen($b) ? -1 : 1;
        }
        return strcmp($a, $b) <=> 0;
    }

    private static function binaryAddBE($a, $b)
    {
        $len = max(strlen($a), strlen($b));
        $a = str_pad($a, $len, "\0", STR_PAD_LEFT);
        $b = str_pad($b, $len, "\0", STR_PAD_LEFT);
        $carry = 0;
        $out = '';
        for ($i = $len - 1; $i >= 0; $i--) {
            $sum = ord($a[$i]) + ord($b[$i]) + $carry;
            $out = chr($sum & 0xff) . $out;
            $carry = $sum >> 8;
        }
        if ($carry > 0) {
            $out = chr($carry) . $out;
        }
        return self::trimBE($out);
    }

    private static function binarySubBE($a, $b)
    {
        $len = max(strlen($a), strlen($b));
        $a = str_pad($a, $len, "\0", STR_PAD_LEFT);
        $b = str_pad($b, $len, "\0", STR_PAD_LEFT);
        $borrow = 0;
        $out = '';
        for ($i = $len - 1; $i >= 0; $i--) {
            $diff = ord($a[$i]) - ord($b[$i]) - $borrow;
            if ($diff < 0) {
                $diff += 256;
                $borrow = 1;
            } else {
                $borrow = 0;
            }
            $out = chr($diff) . $out;
        }
        return self::trimBE($out);
    }

    public static function buildNaiveV2rayNUri($uuid, $server)
    {
        $tlsSettings = $server['tls_settings'] ?? [];
        $params = [
            'security' => 'tls',
        ];
        if (!empty($tlsSettings['server_name'])) {
            $params['sni'] = $tlsSettings['server_name'];
        }
        $name = self::encodeURIComponent($server['name']);
        if (empty($params)) {
            return self::buildSimpleUriString('naive+https', "{$uuid}:{$uuid}", $server, $name);
        }
        return self::buildUriString('naive+https', "{$uuid}:{$uuid}", $server, $name, $params);
    }

    public static function buildNaiveShadowrocketUri($uuid, $server)
    {
        $tlsSettings = $server['tls_settings'] ?? [];
        $params = [];
        if (!empty($tlsSettings['server_name'])) {
            $params['sni'] = $tlsSettings['server_name'];
            $params['peer'] = $tlsSettings['server_name'];
        }
        if (($tlsSettings['allow_insecure'] ?? 0) == 1) {
            $params['allowInsecure'] = 1;
        }

        $name = self::encodeURIComponent($server['name']);
        if (empty($params)) {
            return self::buildSimpleUriString('http2', "{$uuid}:{$uuid}", $server, $name);
        }
        return self::buildUriString('http2', "{$uuid}:{$uuid}", $server, $name, $params);
    }

    /**
     * Generate ECH (Encrypted Client Hello) key pair for sing-box.
     * Produces ech_key (MarshalECHKeys format, for server inbound)
     * and ech_config (ECHConfigList, for client outbound).
     *
     * @param string $outerSni The cover/front domain for the outer ClientHello SNI (public_name).
     *                         This is the FAKE domain visible to network observers.
     *                         The real server_name is encrypted in the inner ClientHello.
     */
    public static function generateEchKeyPair($outerSni)
    {
        $privateKey = random_bytes(32);
        $publicKey = sodium_crypto_scalarmult_base($privateKey);

        $configId = random_int(0, 255);

        // ECHConfig contents per draft-ietf-tls-esni
        $configData = pack('C', $configId);              // config_id
        $configData .= pack('n', 0x0020);                // kem_id: DHKEM(X25519, HKDF-SHA256)
        $configData .= pack('n', 32) . $publicKey;       // public_key with length prefix
        // cipher suites: {HKDF-SHA256, AES-128-GCM}, {HKDF-SHA256, AES-256-GCM}, {HKDF-SHA256, ChaCha20-Poly1305}
        $suites = pack('nnnnnn', 0x0001, 0x0001, 0x0001, 0x0002, 0x0001, 0x0003);
        $configData .= pack('n', strlen($suites)) . $suites;
        $configData .= pack('C', 0);                     // maximum_name_length
        $configData .= pack('C', strlen($outerSni)) . $outerSni; // public_name (cover domain, NOT real SNI)
        $configData .= pack('n', 0);                     // extensions (empty)

        // ECHConfig = version(0xfe0d) + length + data
        $echConfig = pack('n', 0xfe0d) . pack('n', strlen($configData)) . $configData;

        // ECHConfigList for client (no outer length prefix, per Go crypto/tls)
        $echConfigList = $echConfig;

        // MarshalECHKeys for server: length-prefixed configs + key entries
        $echKeys = pack('n', strlen($echConfig)) . $echConfig;
        $echKeys .= pack('n', 1);                        // num_keys = 1
        $echKeys .= pack('C', $configId);                // config_id
        $echKeys .= pack('n', 32) . $privateKey;         // private key with length prefix

        return [
            'ech_key' => base64_encode($echKeys),
            'ech_config' => base64_encode($echConfigList),
        ];
    }

    public static function configureNetworkSettings($server, &$config)
    {
        $network = $server['network'];
        $settings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);

        switch ($network) {
            case 'tcp':
                self::configureTcpSettings($settings, $config);
                break;
            case 'ws':
                self::configureWsSettings($settings, $config);
                break;
            case 'grpc':
                self::configureGrpcSettings($settings, $config);
                break;
            case 'kcp':
                self::configureKcpSettings($settings, $config);
                break;
            case 'httpupgrade':
                self::configureHttpupgradeSettings($settings, $config);
                break;
            case 'xhttp':
                self::configureXhttpSettings($settings, $config);
                break;
        }
    }

    public static function configureTcpSettings($settings, &$config)
    {
        $header = $settings['header'] ?? [];
        if (isset($header['type']) && $header['type'] === 'http') {
            $config['headerType'] = 'http';
            $config['host'] = $header['request']['headers']['Host'][0] ?? '';
            $config['path'] = $header['request']['path'][0] ?? '';
        }
    }

    public static function configureWsSettings($settings, &$config)
    {
        $config['path'] = $settings['path'] ?? '';
        $config['host'] = $settings['headers']['Host'] ?? '';
    }

    public static function configureGrpcSettings($settings, &$config)
    {
        $config['serviceName'] = $settings['serviceName'] ?? '';
    }

    public static function configureKcpSettings($settings, &$config)
    {
        $config['headerType'] = $settings['header']['type'] ?? 'none';
        if (isset($settings['seed'])) {
            $config['seed'] = $settings['seed'];
        }
    }

    public static function configureHttpupgradeSettings($settings, &$config)
    {
        $config['path'] = $settings['path'] ?? '';
        $config['host'] = $settings['host'] ?? '';
    }

    public static function configureXhttpSettings($settings, &$config)
    {
        $config['path'] = $settings['path'] ?? '';
        $config['host'] = $settings['host'] ?? '';
        $config['mode'] = $settings['mode'] ?? 'auto';
        $config['extra'] = isset($settings['extra']) ? json_encode($settings['extra'], JSON_UNESCAPED_SLASHES) : null;
    }
}
