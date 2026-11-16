package database

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

func ConnectDB() *sql.DB {
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		log.Fatal("DATABASE_URL is not configured")
	}

	sqlDB, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatalf("Failed to open PostgreSQL connection: %v", err)
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		log.Fatalf("PostgreSQL connection failed: %v", err)
	}

	log.Println("PostgreSQL connected successfully!")

	return sqlDB
}
