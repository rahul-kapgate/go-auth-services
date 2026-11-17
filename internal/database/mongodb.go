package database

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

func ConnectDB(ctx context.Context) (*mongo.Client, *mongo.Database, error) {
	uri := strings.TrimSpace(os.Getenv("MONGODB_URI"))
	if uri == "" {
		return nil, nil, fmt.Errorf("MONGODB_URI is not configured")
	}

	dbName := strings.TrimSpace(os.Getenv("MONGODB_DATABASE"))
	if dbName == "" {
		return nil, nil, fmt.Errorf("MONGODB_DATABASE is not configured")
	}

	clientOptions := options.Client().
		ApplyURI(uri).
		SetServerAPIOptions(
			options.ServerAPI(options.ServerAPIVersion1),
		).
		SetServerSelectionTimeout(10 * time.Second)

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("MongoDB connection failed: %w", err)
	}

	// Verify connection.
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		disconnectCtx, disconnectCancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer disconnectCancel()

		_ = client.Disconnect(disconnectCtx)

		return nil, nil, fmt.Errorf("MongoDB ping failed: %w", err)
	}

	db := client.Database(dbName)

	return client, db, nil
}
