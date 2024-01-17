CREATE TABLE Users (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    Username VARCHAR(255) NOT NULL,
    Email VARCHAR(255) NOT NULL UNIQUE,
    PasswordHash VARCHAR(512) NOT NULL, -- Erhöhte Länge für stärkere Hashes
    PublicKey TEXT,
    CreationDate DATETIME DEFAULT CURRENT_TIMESTAMP,  -- Datum der Benutzererstellung
    LastLogin DATETIME,  -- Letzter Login-Zeitpunkt (?)
    Status VARCHAR(50)  -- Benutzerstatus (aktiv/inaktiv) (?)
);
CREATE TABLE Files (
    FileID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL, -- Sicherstellung, dass jeder Datei ein User zugeordnet ist
    FileName VARCHAR(255) NOT NULL,
    FilePath TEXT NOT NULL, -- falls die Datei nicht direkt aufm SQL-Server liegt sondern irgendwo aufm PC zB.
    FileData BLOB, -- falls die Datei direkt auf dem SQL-Server in Form einer PDF o.Ä. liegen soll. (kann aber bei großen Dateien die Performance beeinflussen)
    EncryptionStatus VARCHAR(50),
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);
CREATE TABLE PublicKeys (
    KeyID INT AUTO_INCREMENT PRIMARY KEY,
    PublicKey TEXT NOT NULL,
    UserID INT NOT NULL,
    FOREIGN KEY(UserID) REFERENCES Users(UserID)
);
CREATE TABLE AccessPermissions (
    AccessID INT AUTO_INCREMENT PRIMARY KEY,
    FileID INT NOT NULL,
    UserID INT NOT NULL,
    AccessType VARCHAR(50),  -- Art des Zugriffs (Lesen, Schreiben, Löschen)
    FOREIGN KEY (FileID) REFERENCES Files(FileID),
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);
CREATE TABLE Encryption (
    EncryptionID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    FileID INT NOT NULL,
    EncryptionType VARCHAR(50), -- Falls notwendig (?)
    KeyLength INT,  -- Schlüssellänge, falls notwendig (?)
    EncryptionDate DATETIME DEFAULT CURRENT_TIMESTAMP,  -- Datum der Schlüsselerstellung (?)
    FOREIGN KEY (UserID) REFERENCES Users(UserID),
    FOREIGN KEY (FileID) REFERENCES Files(FileID)
);
CREATE TABLE SecurityLogs (
    LogID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT,
    Event TEXT,
    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);

-- Indexierung für häufig abgefragte Felder
CREATE INDEX idx_username ON Users(Username);
CREATE INDEX idx_email ON Users(Email);
CREATE INDEX idx_filename ON Files(FileName);