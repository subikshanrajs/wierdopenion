<?php
// login.php - Handle user login
require_once 'config.php';

startSecureSession();

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

class UserLogin {
    private $db;
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    public function login($credentials) {
        $errors = [];
        
        // Validate input
        if (empty($credentials['username'])) {
            $errors['username'] = 'Username or email is required';
        }
        
        if (empty($credentials['password'])) {
            $errors['password'] = 'Password is required';
        }
        
        if (!empty($errors)) {
            return ['success' => false, 'errors' => $errors];
        }
        
        // Check rate limiting (prevent brute force attacks)
        if ($this->isRateLimited()) {
            return [
                'success' => false, 
                'message' => 'Too many login attempts. Please wait before trying again.',
                'rate_limited' => true
            ];
        }
        
        // Authenticate user
        return $this->authenticateUser($credentials);
    }
    
    private function isRateLimited() {
        // Simple rate limiting - max 5 attempts per IP in 15 minutes
        if (!isset($_SESSION['login_attempts'])) {
            $_SESSION['login_attempts'] = [];
        }
        
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $currentTime = time();
        $timeWindow = 15 * 60; // 15 minutes
        
        // Clean old attempts
        $_SESSION['login_attempts'] = array_filter(
            $_SESSION['login_attempts'],
            function($timestamp) use ($currentTime, $timeWindow) {
                return ($currentTime - $timestamp) < $timeWindow;
            }
        );
        
        // Check if rate limit exceeded
        $ipAttempts = array_filter($_SESSION['login_attempts'], function($attempt) use ($ipAddress) {
            return $attempt['ip'] === $ipAddress;
        });
        
        return count($ipAttempts) >= 5;
    }
    
    private function recordLoginAttempt($success = false) {
        if (!isset($_SESSION['login_attempts'])) {
            $_SESSION['login_attempts'] = [];
        }
        
        if (!$success) {
            $_SESSION['login_attempts'][] = [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'timestamp' => time()
            ];
        } else {
            // Clear attempts on successful login
            $_SESSION['login_attempts'] = [];
        }
    }
    
    private function authenticateUser($credentials) {
        try {
            // Find user by username or email
            $stmt = $this->db->prepare("
                SELECT id, username, email, password_hash, is_active, last_login 
                FROM users 
                WHERE (username = ? OR email = ?) AND is_active = 1
            ");
            
            $identifier = sanitizeInput($credentials['username']);
            $stmt->execute([$identifier, $identifier]);
            $user = $stmt->fetch();
            
            if (!$user) {
                $this->recordLoginAttempt(false);
                return [
                    'success' => false,
                    'message' => 'Invalid username/email or password',
                    'errors' => ['credentials' => 'Check your credentials and try again']
                ];
            }
            
            // Verify password
            if (!password_verify($credentials['password'], $user['password_hash'])) {
                $this->recordLoginAttempt(false);
                return [
                    'success' => false,
                    'message' => 'Invalid username/email or password',
                    'errors' => ['credentials' => 'Check your credentials and try again']
                ];
            }
            
            // Authentication successful
            $this->recordLoginAttempt(true);
            
            // Update last login
            $this->updateLastLogin($user['id']);
            
            // Create session
            $sessionToken = $this->createUserSession($user);
            
            return [
                'success' => true,
                'message' => 'Login successful! Welcome back!',
                'data' => [
                    'user_id' => $user['id'],
                    'username' => $user['username'],
                    'email' => $user['email'],
                    'session_token' => $sessionToken,
                    'last_login' => $user['last_login']
                ]
            ];
            
        } catch (PDOException $e) {
            error_log("Database error in authenticateUser: " . $e->getMessage());
            return ['success' => false, 'message' => 'Login failed. Please try again.'];
        }
    }
    
    private function updateLastLogin($userId) {
        try {
            $stmt = $this->db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
            $stmt->execute([$userId]);
        } catch (PDOException $e) {
            error_log("Error updating last login: " . $e->getMessage());
        }
    }
    
    private function createUserSession($user) {
        try {
            // Generate session token
            $sessionToken = generateSecureToken();
            $expiresAt = date('Y-m-d H:i:s', time() + (30 * 24 * 60 * 60)); // 30 days
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            
            // Deactivate old sessions (optional - keep only one active session)
            $stmt = $this->db->prepare("UPDATE user_sessions SET is_active = 0 WHERE user_id = ?");
            $stmt->execute([$user['id']]);
            
            // Create new session
            $stmt = $this->db->prepare("
                INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$user['id'], $sessionToken, $expiresAt, $ipAddress, $userAgent]);
            
            // Set PHP session variables
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['session_token'] = $sessionToken;
            
            return $sessionToken;
            
        } catch (PDOException $e) {
            error_log("Error creating user session: " . $e->getMessage());
            return generateSecureToken(); // Return a token even if DB insert fails
        }
    }
    
    public function logout($sessionToken = null) {
        try {
            if ($sessionToken) {
                // Deactivate specific session
                $stmt = $this->db->prepare("UPDATE user_sessions SET is_active = 0 WHERE session_token = ?");
                $stmt->execute([$sessionToken]);
            } elseif (isset($_SESSION['user_id'])) {
                // Deactivate all user sessions
                $stmt = $this->db->prepare("UPDATE user_sessions SET is_active = 0 WHERE user_id = ?");
                $stmt->execute([$_SESSION['user_id']]);
            }
            
            // Destroy PHP session
            session_destroy();
            
            return ['success' => true, 'message' => 'Logged out successfully'];
            
        } catch (PDOException $e) {
            error_log("Error during logout: " . $e->getMessage());
            session_destroy(); // Still destroy session even if DB update fails
            return ['success' => true, 'message' => 'Logged out successfully'];
        }
    }
    
    public function checkSession($sessionToken) {
        try {
            $stmt = $this->db->prepare("
                SELECT us.user_id, us.expires_at, u.username, u.email, u.is_active
                FROM user_sessions us
                JOIN users u ON us.user_id = u.id
                WHERE us.session_token = ? AND us.is_active = 1 AND us.expires_at > NOW() AND u.is_active = 1
            ");
            
            $stmt->execute([$sessionToken]);
            $session = $stmt->fetch();
            
            if ($session) {
                return [
                    'success' => true,
                    'data' => [
                        'user_id' => $session['user_id'],
                        'username' => $session['username'],
                        'email' => $session['email']
                    ]
                ];
            }
            
            return ['success' => false, 'message' => 'Invalid or expired session'];
            
        } catch (PDOException $e) {
            error_log("Error checking session: " . $e->getMessage());
            return ['success' => false, 'message' => 'Session check failed'];
        }
    }
}

// Handle different login-related requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get JSON input or form data
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    // If JSON decode failed, try to get form data
    if (json_last_error() !== JSON_ERROR_NONE) {
        $data = $_POST;
    }
    
    if (empty($data)) {
        errorResponse('No data received', 400);
    }
    
    $login = new UserLogin($db);
    
    // Handle different actions
    $action = $data['action'] ?? 'login';
    
    switch ($action) {
        case 'login':
            if (empty($data['username']) && empty($data['password'])) {
                errorResponse('Username and password are required', 400);
            }
            
            $result = $login->login($data);
            
            if ($result['success']) {
                successResponse($result['message'], $result['data']);
            } else {
                $statusCode = isset($result['rate_limited']) ? 429 : (isset($result['errors']) ? 422 : 400);
                $errors = $result['errors'] ?? [];
                errorResponse($result['message'], $statusCode, $errors);
            }
            break;
            
        case 'logout':
            $sessionToken = $data['session_token'] ?? $_SESSION['session_token'] ?? null;
            $result = $login->logout($sessionToken);
            successResponse($result['message']);
            break;
            
        case 'check_session':
            if (empty($data['session_token'])) {
                errorResponse('Session token required', 400);
            }
            
            $result = $login->checkSession($data['session_token']);
            
            if ($result['success']) {
                successResponse('Session valid', $result['data']);
            } else {
                errorResponse($result['message'], 401);
            }
            break;
            
        default:
            errorResponse('Invalid action', 400);
    }
} else {
    errorResponse('Method not allowed', 405);
}
?>