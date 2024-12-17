package database

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
)

// RunMigrations reads and executes all SQL files from the migrations directory
func RunMigrations(db *sql.DB) {
	migrationFiles := []string{
		"db/migrations/conversations.sql", // Add more files as needed
		"db/migrations/messages.sql",
		"db/migrations/users.sql",
	}

	for _, file := range migrationFiles {
		applyMigration(db, file)
	}
}

func applyMigration(db *sql.DB, filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read migration file %s: %v", filePath, err)
	}

	_, err = db.Exec(string(content))
	if err != nil {
		log.Fatalf("Failed to apply migration %s: %v", filePath, err)
	}

	log.Printf("Successfully applied migration: %s", filepath.Base(filePath))
}
