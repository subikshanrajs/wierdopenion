<?php
// logout.php - Handle user logout
require_once 'config.php';

startSecureSession();

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Get session token if provided
        $input = file_get_contents('php://input');
        $data = json_decode($input, true);
        $sessionToken = $data['session_token'] ?? $_SESSION['session_token'] ?? null;
        
        // Deactivate session in database if token exists
        if ($sessionToken && isset($_SESSION['user_id'])) {
            $stmt = $db->prepare("UPDATE user_sessions SET is_active = 0 WHERE session_token = ? AND user_id = ?");
            $stmt->execute([$sessionToken, $_SESSION['user_id']]);
        }
        
        // Clear all session data
        $_SESSION = [];
        
        // Delete the session cookie
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 3600, '/');
        }
        
        // Destroy the session
        session_destroy();
        
        successResponse('Logged out successfully');
        
    } catch (Exception $e) {
        error_log("Logout error: " . $e->getMessage());
        // Still destroy session even if database operation fails
        session_destroy();
        successResponse('Logged out successfully');
    }
} else {
    errorResponse('Method not allowed', 405);
}
?>