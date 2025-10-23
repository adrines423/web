<?php
// get.php
// Servir un M3U tras autenticar usuario/contraseña.
// Recomendado: ejecutar sobre HTTPS.

// ===== CONFIG =====
// Ruta a archivo JSON con usuarios y contraseñas hasheadas (ver abajo)
define('USERS_FILE', __DIR__ . '/users.json');
// Nombre del fichero de log (opc.)
define('AUTH_LOG', __DIR__ . '/auth.log');
// Tiempo en segundos para bloquear reintentos rápidos (simple rate-limiting)
define('MIN_REQUEST_INTERVAL', 1);

// ===== Helpers =====
function log_auth($user, $success, $note = '') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $time = date('Y-m-d H:i:s');
    $line = "[$time] IP=$ip USER=$user SUCCESS=" . ($success ? '1' : '0') . " NOTE=$note\n";
    @file_put_contents(AUTH_LOG, $line, FILE_APPEND | LOCK_EX);
}

// Cargar usuarios desde JSON: {"usuario":"$2y$...hash...","otro":"$2y$..."}
function load_users() {
    $file = USERS_FILE;
    if (!is_readable($file)) return [];
    $json = file_get_contents($file);
    $data = json_decode($json, true);
    return is_array($data) ? $data : [];
}

// Timing-safe string compare wrapper
function safe_equals($a, $b) {
    if (function_exists('hash_equals')) return hash_equals((string)$a, (string)$b);
    // fallback
    return (string)$a === (string)$b;
}

// Obtener credenciales: prefer Basic Auth, luego GET params
function get_credentials() {
    // Basic Auth
    if (!empty($_SERVER['PHP_AUTH_USER'])) {
        return [$_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ?? ''];
    }
    // Alternate: some servers put them in HTTP_AUTHORIZATION
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        if (stripos($_SERVER['HTTP_AUTHORIZATION'], 'basic ') === 0) {
            $encoded = substr($_SERVER['HTTP_AUTHORIZATION'], 6);
            $decoded = base64_decode($encoded);
            if ($decoded !== false) {
                $parts = explode(':', $decoded, 2);
                if (count($parts) === 2) return [$parts[0], $parts[1]];
            }
        }
    }
    // GET (no recomendado) ?user=...&pass=...
    $u = isset($_GET['user']) ? $_GET['user'] : null;
    $p = isset($_GET['pass']) ? $_GET['pass'] : null;
    if ($u !== null && $p !== null) return [$u, $p];

    return [null, null];
}

// Enviar 401 para Basic Auth
function send_401($realm = 'Restricted') {
    header('HTTP/1.1 401 Unauthorized');
    header('WWW-Authenticate: Basic realm="' . addslashes($realm) . '"');
    echo "401 Unauthorized\n";
    exit;
}

// ===== MAIN =====
$users = load_users();
list($user, $pass) = get_credentials();

// simple anti-flood via last-request timestamp per IP (optional)
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$stampFile = sys_get_temp_dir() . "/get_m3u_lastreq_" . preg_replace('/[^a-zA-Z0-9_]/','_',$ip);
if (file_exists($stampFile)) {
    $last = (int)file_get_contents($stampFile);
    if (time() - $last < MIN_REQUEST_INTERVAL) {
        // Too many requests in short time
        log_auth($user ?? 'n/a', false, 'rate_limit');
        header('HTTP/1.1 429 Too Many Requests');
        echo "429 Too Many Requests\n";
        exit;
    }
}
@file_put_contents($stampFile, (string)time());

// Validate presence
if (empty($user) || empty($pass)) {
    // If attempted Basic, ask for credentials; otherwise show minimal message
    log_auth($user ?? 'n/a', false, 'missing_credentials');
    send_401('M3U Access');
}

// Check user exists
if (!array_key_exists($user, $users)) {
    log_auth($user, false, 'user_not_found');
    send_401('M3U Access');
}

// Verify password (stored as password_hash)
$hash = $users[$user];
if (!password_verify($pass, $hash)) {
    log_auth($user, false, 'bad_password');
    send_401('M3U Access');
}

// Optionally: check password needs rehash and update users.json (not implemented here)

// Auth success
log_auth($user, true, 'ok');

// ===== Generate M3U content for this user =====
// Build M3U dynamically. Customize según tu sistema: rutas, tokens, expiración, etc.
// IMPORTANT: escape/sanitize any user-provided values inserted into playlist.
function esc($s) {
    return str_replace(["\r","\n"], '', (string)$s);
}

// Example: per-user stream URL (this is placeholder — ajusta a tus rutas reales)
$stream_base = 'https://streams.example.com/live'; // cambia a tu servidor de streaming
$playlist_name = 'MiPlaylist ' . esc($user);
$stream_url = $stream_base . '/' . rawurlencode($user) . '/index.m3u8'; // ejemplo

$m3u = "#EXTM3U\n";
$m3u .= "#PLAYLIST: " . $playlist_name . "\n";
$m3u .= "#EXTINF:-1, Canal de ejemplo para " . $playlist_name . "\n";
$m3u .= $stream_url . "\n";
// Añade más líneas si lo necesitas...

// ===== Entregar fichero con cabeceras correctas =====
$filename = 'playlist_' . preg_replace('/[^a-zA-Z0-9_\-]/','_', $user) . '.m3u';
header('Content-Type: audio/x-mpegurl; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . strlen($m3u));
echo $m3u;
exit;
