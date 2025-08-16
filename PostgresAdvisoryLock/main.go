// TransactionLock - Создает транзакционную блокировку на уровне PostgreSQL, связанную с заданным ключом.
func TransactionLock(ctx context.Context, transaction pgx.Tx, lockID uuid.UUID) error {
	hasher := fnv.New64()
	_, err := hasher.Write(lockID[:])
	if err != nil {
		return fmt.Errorf("failed to hash lockID %q: %w", lockID, err)
	}

	_, err = transaction.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(hasher.Sum64()))
	if err != nil {
		return fmt.Errorf("failed to advisory xact lock with lockID %q: %w", lockID, err)
	}
	return nil
}

// SessionLock - Создает сессионную блокировку на уровне PostgreSQL, связанную с заданным ключом.
func SessionLock(ctx context.Context, transaction pgx.Tx, lockID uuid.UUID) error {
	hasher := fnv.New64()
	_, err := hasher.Write(lockID[:])
	if err != nil {
		return fmt.Errorf("failed to hash lockID %q: %w", lockID, err)
	}

	_, err = transaction.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(hasher.Sum64()))
	if err != nil {
		return fmt.Errorf("failed to advisory lock with lockID %q: %w", lockID, err)
	}
	return nil
}

// SessionUnlock - Снимает сессионную блокировку на уровне PostgreSQL, связанную с заданным ключом.
func SessionUnlock(ctx context.Context, transaction pgx.Tx, lockID uuid.UUID) error {
	hasher := fnv.New64()
	_, err := hasher.Write(lockID[:])
	if err != nil {
		return fmt.Errorf("failed to hash lockID %q: %w", lockID, err)
	}

	var result bool
	err = transaction.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", int64(hasher.Sum64())).Scan(&result)
	if err != nil {
		return fmt.Errorf("failed to advisory unlock with lockID %q: %w", lockID, err)
	}
	if !result {
		return fmt.Errorf("unable to advisory unlock with lockID %q: lock was not held", lockID)
	}
	return nil
}
