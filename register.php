<?php
// register.php - Handle user registration
require_once 'config.php';

startSecureSession();

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

class UserRegistration {
    private $db;
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    public function register($userData) {
        $errors = [];
        
        // Validate input data
        if (empty($userData['username'])) {
            $errors['username'] = 'Username is required';
        } elseif (!isValidUsername($userData['username'])) {
            $errors['username'] = 'Username must be 3-30 characters and contain only letters, numbers, and underscores';
        }
        
        if (empty($userData['email'])) {
            $errors['email'] = 'Email is required';
        } elseif (!isValidEmail($userData['email'])) {
            $errors['email'] = 'Please enter a valid email address';
        }
        
        if (empty($userData['password'])) {
            $errors['password'] = 'Password is required';
        } elseif (!isValidPassword($userData['password'])) {
            $errors['password'] = 'Password must be at least 8 characters long';
        }
        
        if (empty($userData['confirm_password'])) {
            $errors['confirm_password'] = 'Please confirm your password';
        } elseif ($userData['password'] !== $userData['confirm_password']) {
            $errors['confirm_password'] = 'Passwords do not match';
        }
        
        if (empty($userData['terms'])) {
            $errors['terms'] = 'You must agree to the terms of service';
        }
        
        // If there are validation errors, return them
        if (!empty($errors)) {
            return ['success' => false, 'errors' => $errors];
        }
        
        // Check if username or email already exists
        $existingUser = $this->checkExistingUser($userData['username'], $userData['email']);
        if ($existingUser) {
            return $existingUser;
        }
        
        // Create new user
        return $this->createUser($userData);
    }
    
    private function checkExistingUser($username, $email) {
        try {
            $stmt = $this->db->prepare("SELECT username, email FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $email]);
            $existingUser = $stmt->fetch();
            
            if ($existingUser) {
                $errors = [];
                if ($existingUser['username'] === $username) {
                    $errors['username'] = 'This username is already taken. Try: ' . $username . rand(1, 999);
                }
                if ($existingUser['email'] === $email) {
                    $errors['email'] = 'An account with this email already exists';
                }
                return ['success' => false, 'errors' => $errors];
            }
            
            return null;
        } catch (PDOException $e) {
            error_log("Database error in checkExistingUser: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error occurred'];
        }
    }
    
    private function createUser($userData) {
        try {
            // Hash the password
            $passwordHash = password_hash($userData['password'], PASSWORD_DEFAULT);
            
            // Generate verification token
            $verificationToken = generateSecureToken();
            
            // Insert new user
            $stmt = $this->db->prepare("
                INSERT INTO users (username, email, password_hash, verification_token, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            
            $stmt->execute([
                sanitizeInput($userData['username']),
                sanitizeInput($userData['email']),
                $passwordHash,
                $verificationToken
            ]);
            
            $userId = $this->db->lastInsertId();
            
            // Set session variables
            $_SESSION['user_id'] = $userId;
            $_SESSION['username'] = $userData['username'];
            $_SESSION['email'] = $userData['email'];
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            
            // Create session token for additional security
            $sessionToken = generateSecureToken();
            $this->createUserSession($userId, $sessionToken);
            $_SESSION['session_token'] = $sessionToken;
            
            return [
                'success' => true,
                'message' => 'Registration successful! Welcome to WierdOpinions!',
                'data' => [
                    'user_id' => $userId,
                    'username' => $userData['username'],
                    'email' => $userData['email'],
                    'session_token' => $sessionToken
                ]
            ];
            
        } catch (PDOException $e) {
            error_log("Database error in createUser: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed. Please try again.'];
        }
    }
    
    private function createUserSession($userId, $sessionToken) {
        try {
            $expiresAt = date('Y-m-d H:i:s', time() + (30 * 24 * 60 * 60)); // 30 days
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            
            $stmt = $this->db->prepare("
                INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([$userId, $sessionToken, $expiresAt, $ipAddress, $userAgent]);
        } catch (PDOException $e) {
            error_log("Error creating user session: " . $e->getMessage());
        }
    }
}

// Handle the registration request
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
    
    $registration = new UserRegistration($db);
    $result = $registration->register($data);
    
    if ($result['success']) {
        successResponse($result['message'], $result['data']);
    } else {
        $statusCode = isset($result['errors']) ? 422 : 400;
        $message = $result['message'] ?? 'Registration failed';
        $errors = $result['errors'] ?? [];
        errorResponse($message, $statusCode, $errors);
    }
} else {
    errorResponse('Method not allowed', 405);
}
?>