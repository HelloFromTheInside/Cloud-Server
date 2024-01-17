CREATE TABLE Users (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    Username VARCHAR(255) NOT NULL,
    PasswordHash VARCHAR(512) NOT NULL, -- Erhöhte Länge für stärkere Hashes
    CreationDate DATETIME DEFAULT CURRENT_TIMESTAMP,  -- Datum der Benutzererstellung
    LastLogin DATETIME  -- Letzter Login-Zeitpunkt
);

-- Indexierung für häufig abgefragte Felder
CREATE INDEX idx_username ON Users(Username);
