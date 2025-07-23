package RepositoriesUnitTesting

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"log"
	"os"
	"testing"
	"time"
)

var (
	pgContainer *postgres.PostgresContainer
	pool        *pgxpool.Pool
	ctx         context.Context
)

func TestMain(m *testing.M) {
	setup()

	code := m.Run()

	teardown()

	os.Exit(code)
}

func setup() {
	setupPgContainer := func() {
		logger := log.Default()
		var err error
		pgContainer, err = postgres.Run(ctx,
			"postgres:16.2",
			postgres.WithOrderedInitScripts(
				"./test-database-schema.sql",
				"./test-database-data.sql",
			),
			postgres.WithDatabase("test"),
			postgres.WithUsername("test"),
			postgres.WithPassword("test"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).WithStartupTimeout(time.Minute)),
			testcontainers.WithLogger(logger),
		)
		if err != nil {
			panic(fmt.Sprintf("failed to run pgContainer: %s", err))
		}
	}
	setupPool := func() {
		connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			panic(fmt.Sprintf("failed to get connection string: %v", err))
		}

		pool, err = pgxpool.New(ctx, connStr)
		if err != nil {
			panic(fmt.Sprintf("failed to connect to database: %v", err))
		}
	}

	ctx = context.Background()
	setupPgContainer()
	setupPool()
}

func Test_Entity_Create_NoError(t *testing.T) {
	// Arrange
	transaction, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}
	defer func() {
		_ = transaction.Rollback(ctx)
	}()

	repository := NewPostgresEntityRepository(transaction)
	require.NotNil(t, repository)

	createEntityInfos := []struct {
		{},
		{}
	}

	// Act
	err = repository.Create(ctx, createEntityInfos)

	// Assert
	require.NoError(t, err)
}

func teardown() {
	pool.Close()

	if err := pgContainer.Terminate(ctx); err != nil {
		panic(fmt.Sprintf("failed to terminate pgContainer: %s", err))
	}
}
