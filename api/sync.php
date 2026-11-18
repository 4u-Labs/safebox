<?php
declare(strict_types=1);
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=utf-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

define('DB_PATH', __DIR__ . '/../database/safepass.db');

function getDb(): PDO {
    $dir = dirname(DB_PATH);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $pdo = new PDO('sqlite:' . DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA journal_mode=WAL');
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS vaults (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE,
            email TEXT UNIQUE NOT NULL,
            display_name TEXT,
            photo_url TEXT,
            vault_data TEXT,
            token TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_vaults_token ON vaults(token);
        CREATE INDEX IF NOT EXISTS idx_vaults_email ON vaults(email);
    ");
    return $pdo;
}

$action = $_GET['action'] ?? '';

try {
    $pdo = getDb();

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'google_auth') {
        $body = json_decode(file_get_contents('php://input'), true) ?? [];
        $credential = trim($body['credential'] ?? '');
        $email = trim($body['email'] ?? '');
        $name = trim($body['name'] ?? '');
        $picture = trim($body['picture'] ?? '');
        $googleId = trim($body['google_id'] ?? '');

        // Decodificar JWT do Google
        if ($credential) {
            $parts = explode('.', $credential);
            if (count($parts) === 3) {
                $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
                if ($payload && !empty($payload['email'])) {
                    $email = $payload['email'];
                    $name = $payload['name'] ?? $name;
                    $picture = $payload['picture'] ?? $picture;
                    $googleId = $payload['sub'] ?? $googleId;
                }
            }
        }

        if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'E-mail inválido']);
            exit;
        }

        $stmt = $pdo->prepare('SELECT * FROM vaults WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        $token = bin2hex(random_bytes(32));

        if ($user) {
            $pdo->prepare('UPDATE vaults SET token = ?, display_name = ?, photo_url = ?, google_id = COALESCE(google_id, ?), updated_at = datetime("now") WHERE id = ?')
                ->execute([$token, $name ?: $user['display_name'], $picture ?: $user['photo_url'], $googleId, $user['id']]);
            $vaultData = $user['vault_data'];
        } else {
            $stmt = $pdo->prepare('INSERT INTO vaults (google_id, email, display_name, photo_url, token, vault_data) VALUES (?, ?, ?, ?, ?, NULL)');
            $stmt->execute([$googleId, $email, $name, $picture, $token]);
            $vaultData = null;
        }

        echo json_encode([
            'success' => true,
            'token' => $token,
            'user' => [
                'email' => $email,
                'name' => $name,
                'picture' => $picture
            ],
            'vault_data' => $vaultData ? json_decode($vaultData, true) : null
        ]);
        exit;
    }

    // Validar token para push e pull
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $token = null;
    if (preg_match('/Bearer\s+(\S+)/i', $authHeader, $m)) {
        $token = $m[1];
    }
    if (!$token && isset($_GET['token'])) {
        $token = $_GET['token'];
    }

    if (!$token) {
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Token não fornecido']);
        exit;
    }

    $stmt = $pdo->prepare('SELECT * FROM vaults WHERE token = ?');
    $stmt->execute([$token]);
    $user = $stmt->fetch();

    if (!$user) {
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Sessão expirada. Faça login novamente.']);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'push') {
        $body = json_decode(file_get_contents('php://input'), true) ?? [];
        $vaultData = $body['vault_data'] ?? null;

        if (!$vaultData) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Dados do cofre ausentes']);
            exit;
        }

        $pdo->prepare('UPDATE vaults SET vault_data = ?, updated_at = datetime("now") WHERE id = ?')
            ->execute([json_encode($vaultData), $user['id']]);

        echo json_encode([
            'success' => true,
            'updated_at' => time()
        ]);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'GET' && $action === 'pull') {
        $vaultData = $user['vault_data'] ? json_decode($user['vault_data'], true) : null;
        echo json_encode([
            'success' => true,
            'vault_data' => $vaultData,
            'user' => [
                'email' => $user['email'],
                'name' => $user['display_name'],
                'picture' => $user['photo_url']
            ],
            'updated_at' => strtotime($user['updated_at'] ?? 'now')
        ]);
        exit;
    }

    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Ação desconhecida']);

} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
