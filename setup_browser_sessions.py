"""
Script to create the browser_sessions table in the database.
Run this script once to set up the browser session tracking table.

Usage:
    python setup_browser_sessions.py
"""
import os
from dotenv import load_dotenv
import mysql.connector

# Load environment variables
load_dotenv()

def create_browser_sessions_table():
    """Create browser_sessions table if it doesn't exist"""
    db_host = os.getenv("DB_HOST", "localhost")
    db_user = os.getenv("DB_USER", "root")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME", "Erp_Db")
    
    if not db_password:
        raise ValueError("DB_PASSWORD is not set in environment variables")
    
    try:
        connection = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )
        cursor = connection.cursor()
        
        # Create browser_sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS browser_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                browser_id VARCHAR(255) NOT NULL UNIQUE,
                user_id INT NOT NULL,
                session_token TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                INDEX idx_browser_id (browser_id),
                INDEX idx_user_id (user_id),
                INDEX idx_expires_at (expires_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        
        connection.commit()
        print("✓ browser_sessions table created successfully!")
        
        cursor.close()
        connection.close()
        
    except mysql.connector.Error as err:
        print(f"Error creating table: {err}")
        raise

if __name__ == "__main__":
    print("Creating browser_sessions table...")
    create_browser_sessions_table()
    print("Setup complete!")

