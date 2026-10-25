
import sqlite3

def create_database():
    connection = sqlite3.connect("trustvault.db")

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    connection.execute("""
         CREATE TABLE IF NOT EXISTS document_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            shared_with TEXT NOT NULL,
            FOREIGN KEY (document_id) REFERENCES documents(id),
            UNIQUE (document_id, shared_with)
        )
    """)
    connection.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        document_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
       )
   """)

    connection.commit()
    connection.close()
    print("TrustVault database created successfully!")

if __name__ == "__main__":
    create_database()
