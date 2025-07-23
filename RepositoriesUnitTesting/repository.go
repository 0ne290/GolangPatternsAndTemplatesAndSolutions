package RepositoriesUnitTesting

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresEntityRepository ...
type PostgresEntityRepository struct {
	transaction pgx.Tx
}

// NewPostgresEntityRepository ...
func NewPostgresEntityRepository(transaction pgx.Tx) *PostgresEntityRepository {
	return &PostgresEntityRepository{transaction}
}

func (r *PostgresEntityRepository) Create(ctx context.Context, createEntityInfos []struct{}) error {
	return nil
}
