/* create table users */
CREATE TABLE users (
            id INT, AUTO INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        );

/* create table game_progress */
CREATE TABLE game_progress (
            id INT, AUTO INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            game_name VARCHAR(255) NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT FALSE,
            completed_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
