
DROP TABLE IF EXISTS disponibilidade;
DROP TABLE IF EXISTS disciplinas;
DROP TABLE IF EXISTS professores;
DROP TABLE IF EXISTS usuarios;

CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('usuario', 'admin') NOT NULL DEFAULT 'usuario'
) ENGINE=InnoDB;

CREATE TABLE professores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(255) UNIQUE NOT NULL
) ENGINE=InnoDB;

CREATE TABLE disciplinas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(255) NOT NULL,
    aulas_semanais INT NOT NULL,
    professor_id INT,
    FOREIGN KEY (professor_id) REFERENCES professores(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE disponibilidade (
    id INT AUTO_INCREMENT PRIMARY KEY,
    professor_id INT NOT NULL,
    dia_semana VARCHAR(20) NOT NULL,
    periodo INT NOT NULL,
    disponivel BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (professor_id, dia_semana, periodo),
    FOREIGN KEY (professor_id) REFERENCES professores(id) ON DELETE CASCADE
) ENGINE=InnoDB;