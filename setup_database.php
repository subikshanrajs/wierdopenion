<?php
// setup_database.php - Run this file once to set up your database
require_once 'config.php';

echo "<h2>WierdOpinions Database Setup</h2>\n";
echo "<pre>\n";

try {
    // Initialize database
    $database = new Database();
    $database->initializeDatabase();
    
    echo "✅ Database setup completed successfully!\n\n";
    
    // Display database information
    echo "Database Information:\n";
    echo "- Host: " . DB_HOST . "\n";
    echo "- Database: " . DB_NAME . "\n";
    echo "- Username: " . DB_USERNAME . "\n";
    echo "\nTables created:\n";
    echo "- users (for user accounts)\n";
    echo "- user_sessions (for session management)\n";
    echo "- questions (for future question functionality)\n";
    
    // Test connection
    $db = $database->getConnection();
    $stmt = $db->query("SHOW TABLES");
    $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    echo "\nVerification - Tables in database:\n";
    foreach ($tables as $table) {
        echo "- $table\n";
    }
    
    echo "\n✅ Database setup verification successful!\n";
    echo "\nNext steps:\n";
    echo "1. Your database is ready to use\n";
    echo "2. Update your HTML forms to submit to the PHP scripts\n";
    echo "3. Test registration and login functionality\n";
    echo "4. You can delete this setup file after successful setup\n";
    
} catch (Exception $e) {
    echo "❌ Database setup failed: " . $e->getMessage() . "\n";
    echo "\nTroubleshooting:\n";
    echo "1. Make sure XAMPP is running\n";
    echo "2. Check if MySQL service is started\n";
    echo "3. Verify database credentials in config.php\n";
    echo "4. Make sure you have permission to create databases\n";
}

echo "</pre>\n";

// Add some helpful information
echo "<h3>Integration Instructions:</h3>";
echo "<p>To integrate with your existing HTML forms, update the form submission JavaScript:</p>";
echo "<pre>";
echo "
// Update your register form submission
document.getElementById('register-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const data = {
        username: formData.get('username') || document.getElementById('username').value,
        email: formData.get('email') || document.getElementById('email').value,
        password: formData.get('password') || document.getElementById('password').value,
        confirm_password: formData.get('confirm_password') || document.getElementById('confirm-password').value,
        terms: document.getElementById('terms').checked
    };
    
    try {
        const response = await fetch('register.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert('🎉 ' + result.message);
            // Redirect to main app
            window.location.href = 'index.html?logged_in=true&username=' + result.data.username;
        } else {
            if (result.errors) {
                let errorMsg = 'Registration failed:\\n';
                for (let field in result.errors) {
                    errorMsg += '- ' + result.errors[field] + '\\n';
                }
                alert(errorMsg);
            } else {
                alert('❌ ' + result.message);
            }
        }
    } catch (error) {
        console.error('Registration error:', error);
        alert('❌ Registration failed. Please try again.');
    }
});

// Update your login form submission  
document.getElementById('login-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const data = {
        username: formData.get('username') || document.getElementById('login-username').value,
        password: formData.get('password') || document.getElementById('login-password').value
    };
    
    try {
        const response = await fetch('login.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert('🚀 ' + result.message);
            // Store session info
            sessionStorage.setItem('user_token', result.data.session_token);
            sessionStorage.setItem('username', result.data.username);
            // Redirect to main app
            window.location.href = 'index.html?logged_in=true&username=' + result.data.username;
        } else {
            if (result.errors) {
                let errorMsg = 'Login failed:\\n';
                for (let field in result.errors) {
                    errorMsg += '- ' + result.errors[field] + '\\n';
                }
                alert(errorMsg);
            } else {
                alert('❌ ' + result.message);
            }
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('❌ Login failed. Please try again.');
    }
});
";
echo "</pre>";

echo "<h3>File Structure:</h3>";
echo "<p>Make sure your files are organized like this in your XAMPP htdocs folder:</p>";
echo "<pre>";
echo "
/xampp/htdocs/wierdopinions/
├── config.php          (Database configuration)
├── register.php        (Registration handler)
├── login.php          (Login handler)
├── setup_database.php (This file - run once)
├── index.html         (Main page)
├── register.html      (Registration page)
├── login.html         (Login page)
└── logout.php         (Optional logout handler)
";
echo "</pre>";

echo "<h3>Testing Your Setup:</h3>";
echo "<ol>";
echo "<li>Visit: <a href='register.html'>register.html</a> to test registration</li>";
echo "<li>Visit: <a href='login.html'>login.html</a> to test login</li>";
echo "<li>Check the browser's Network tab in Developer Tools to see API responses</li>";
echo "<li>Check XAMPP logs for any PHP errors</li>";
echo "</ol>";
?>