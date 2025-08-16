// -----------------------------------------------------------------------------------------------------------------------------------
// Server

type Server struct {
	srv        *http.Server
	pgxPool    *pgxpool.Pool
	logger     *zap.SugaredLogger
	jwtManager *jwt.Manager
}

func NewServer(cfg *config.Config, pgxPool *pgxpool.Pool, logger *zap.SugaredLogger, jwtManager *jwt.Manager) *Server {
	server := &Server{
		srv: &http.Server{
			Addr:              cfg.HTTPAddress,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
		},
		pgxPool:    pgxPool,
		logger:     logger,
		jwtManager: jwtManager,
	}

	server.AddRoutes()

	return server
}

func (s *Server) AddRoutes() {
	service := handlers.NewService(
		s.pgxPool,
		s.logger,
		repositories.NewPostgresDeviceRepository(s.pgxPool),
		repositories.NewPostgresUserRepository(s.pgxPool),
		repositories.NewPostgresProductionLineRepository(s.pgxPool),
	)

	r := chi.NewRouter()

	r.Use(middlewares.RecoveryAndLogging(s.logger))
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/health", handlers.HealthcheckHandler(s.pgxPool))

	// Одиночные операции; требуется токен девайсов
	r.Route("/device", func(r chi.Router) {
		r.Use(middlewares.DeviceAuth(s.jwtManager))
		r.Get("/", service.GetDevice)
		r.Patch("/", service.UpdateDevice)
	})

	// Массовые операции; требуется токен юзеров
	r.Route("/devices", func(r chi.Router) {
		r.Use(middlewares.UserAuth(s.jwtManager))
		r.Post("/", service.BulkCreateDevice)
		r.Get("/", service.BulkGetDevice)
		r.Patch("/", service.BulkUpdateDevice)
		r.Delete("/", service.BulkDeleteDevice)
	})

	s.srv.Handler = r
}

func (s *Server) Run() error {
	errChan := make(chan error, 1)

	go func() {
		s.logger.Info(fmt.Sprintf("server starting on %s", s.srv.Addr))
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("HTTP server failed to start on %s: %w", s.srv.Addr, err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return err
	case sig := <-quit:
		s.logger.Info("shutdown signal received", "signal", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s.logger.Info("shutting down server...")
	if err := s.srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server graceful shutdown failed: %w", err)
	}

	s.logger.Info("server shutdown complete")

	return nil
}

// Server
// -----------------------------------------------------------------------------------------------------------------------------------
// Handlers

func (s *Service) BulkUpdateDevice(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Message string `json:"message"`
	}

	ctx := r.Context()

	var req []models.UpdateDeviceInfo
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respond.JSON(w, http.StatusBadRequest, response{"request format is invalid"})

		return
	}
	if len(req) == 0 {
		respond.JSON(w, http.StatusBadRequest, response{"at least one device must be updated"})

		return
	}

	userID := middlewares.GetUserIDFromContext(ctx)
	if userID == uuid.Nil {
		respond.JSON(w, http.StatusUnauthorized, response{"invalid user ID"})

		return
	}

	userCompanyID, err := s.userRepository.GetCompanyIDByID(ctx, userID)
	if err != nil {
		if errors.Is(err, okto_errors.ErrNotFound) {
			respond.JSON(w, http.StatusUnauthorized, response{err.Error()})

			return
		}
		respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

		return
	}

	for _, updateDeviceInfo := range req {
		if updateDeviceInfo.ProductionLineID != uuid.Nil {
			productionLineCompanyID, err := s.productionLineRepository.GetCompanyIDByID(ctx, updateDeviceInfo.ProductionLineID)
			if err != nil {
				if errors.Is(err, okto_errors.ErrNotFound) {
					respond.JSON(w, http.StatusBadRequest, response{err.Error()})

					return
				}
				respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

				return
			}
			if productionLineCompanyID != userCompanyID {
				respond.JSON(w, http.StatusForbidden, response{fmt.Sprintf("production line \"%s\" belongs to another company",
					updateDeviceInfo.ProductionLineID.String())})

				return
			}
		}
	}

	postgresTransaction, err := s.postgresConnectionPool.Begin(ctx)
	if err != nil {
		respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

		return
	}
	defer func() {
		_ = postgresTransaction.Rollback(ctx)
	}()

	err = s.deviceRepository.BulkUpdate(ctx, postgresTransaction, userCompanyID, req)
	if err != nil {
		if errors.Is(err, okto_errors.ErrNotFound) {
			respond.JSON(w, http.StatusBadRequest, response{err.Error()})

			return
		}
		respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

		return
	}

	err = postgresTransaction.Commit(ctx)
	if err != nil {
		respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

		return
	}

	respond.JSON(w, http.StatusOK, response{"devices is updated"})
}

func (s *Service) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Message string `json:"message"`
	}

	ctx := r.Context()

	var req models.UpdateDeviceInfo
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respond.JSON(w, http.StatusBadRequest, response{"request format is invalid"})

		return
	}

	req.DeviceID = middlewares.GetDeviceIDFromContext(ctx)
	if req.DeviceID == uuid.Nil {
		respond.JSON(w, http.StatusUnauthorized, response{"invalid device ID"})

		return
	}

	deviceCompanyID, err := s.deviceRepository.GetCompanyIDByID(ctx, req.DeviceID)
	if err != nil {
		if errors.Is(err, okto_errors.ErrNotFound) {
			respond.JSON(w, http.StatusUnauthorized, response{err.Error()})

			return
		}
		respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

		return
	}

	if req.ProductionLineID != uuid.Nil {
		productionLineCompanyID, err := s.productionLineRepository.GetCompanyIDByID(ctx, req.ProductionLineID)
		if err != nil {
			if errors.Is(err, okto_errors.ErrNotFound) {
				respond.JSON(w, http.StatusBadRequest, response{err.Error()})

				return
			}
			respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

			return
		}
		if productionLineCompanyID != deviceCompanyID {
			respond.JSON(w, http.StatusForbidden, fmt.Sprintf("production line \"%s\" belongs to another company",
				req.ProductionLineID.String()))

			return
		}
	}

	postgresTransaction, err := s.postgresConnectionPool.Begin(ctx)
	if err != nil {
		respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

		return
	}
	defer func() {
		_ = postgresTransaction.Rollback(ctx)
	}()

	err = s.deviceRepository.Update(ctx, postgresTransaction, deviceCompanyID, req)
	if err != nil {
		if errors.Is(err, okto_errors.ErrNotFound) {
			respond.JSON(w, http.StatusBadRequest, response{err.Error()})

			return
		}
		respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

		return
	}

	err = postgresTransaction.Commit(ctx)
	if err != nil {
		respond.Send500(w, s.logger, err, middlewares.GetRequestIDFromContext(ctx))

		return
	}

	respond.JSON(w, http.StatusOK, response{"device is updated"})
}

// Handlers
// -----------------------------------------------------------------------------------------------------------------------------------
// Middlewares -> autn

func DeviceAuth(jwtManager *jwt.Manager) func(http.Handler) http.Handler {
	type response struct {
		Message string `json:"message"`
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			splittedAuthHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
			if len(splittedAuthHeader) == 2 {
				claims, err := jwtManager.ValidateAndParseDeviceAccessToken(splittedAuthHeader[1])
				if err != nil {
					respond.JSON(w, http.StatusUnauthorized, response{err.Error()})

					return
				}
				// Андройды пока еще не обновляют свои токены. Раскомментировать этот код, когда андройды остепенятся.
				/*if claims.ExpirationAt <= time.Now().Unix() {
					return okto_errors.NewAuthenticationViolationError("access token is expired")
				}*/

				ctx := SetDeviceID(r.Context(), claims.DeviceID)
				next.ServeHTTP(w, r.WithContext(ctx))

				return
			}

			respond.JSON(w, http.StatusUnauthorized, response{"access token is required"})
		})
	}
}

func UserAuth(jwtManager *jwt.Manager) func(http.Handler) http.Handler {
	type response struct {
		Message string `json:"message"`
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			splittedAuthHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
			if len(splittedAuthHeader) == 2 {
				claims, err := jwtManager.ValidateAndParseUserAccessToken(splittedAuthHeader[1])
				if err != nil {
					respond.JSON(w, http.StatusUnauthorized, response{err.Error()})

					return
				}
				if claims.ExpirationAt <= time.Now().Unix() {
					respond.JSON(w, http.StatusUnauthorized, response{"access token is expired"})

					return
				}

				ctx := SetUserID(r.Context(), claims.UserID)
				next.ServeHTTP(w, r.WithContext(ctx))

				return
			}

			respond.JSON(w, http.StatusUnauthorized, response{"access token is required"})
		})
	}
}

// Middlewares -> autn
// -----------------------------------------------------------------------------------------------------------------------------------
// Middlewares -> context

type contextKey string

const (
	userIDKey    contextKey = "userID"
	deviceIDKey  contextKey = "deviceID"
	requestIDKey contextKey = "requestID"
)

func SetUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

func SetDeviceID(ctx context.Context, deviceID uuid.UUID) context.Context {
	return context.WithValue(ctx, deviceIDKey, deviceID)
}

func SetRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

func GetUserIDFromContext(ctx context.Context) uuid.UUID {
	if userID, ok := ctx.Value(userIDKey).(uuid.UUID); ok {
		return userID
	}
	return uuid.Nil
}

func GetDeviceIDFromContext(ctx context.Context) uuid.UUID {
	if deviceID, ok := ctx.Value(deviceIDKey).(uuid.UUID); ok {
		return deviceID
	}
	return uuid.Nil
}

func GetRequestIDFromContext(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// Middlewares -> context
// -----------------------------------------------------------------------------------------------------------------------------------
// Middlewares -> recovery_and_logging

func RecoveryAndLogging(logger *zap.SugaredLogger) func(http.Handler) http.Handler {
	type response struct {
		Message string `json:"message"`
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			requestID := uuid.New().String()
			ctx := SetRequestID(r.Context(), requestID)
			crw := &customResponseWriter{ResponseWriter: w}

			defer func() {
				if err := recover(); err != nil {
					logger.Errorw("panic recovered",
						"requestID", requestID,
						"error", err,
						"stack trace", string(debug.Stack()),
					)
					respond.JSON(w, http.StatusInternalServerError, response{
						fmt.Sprintf("Please report the issue to technical support and attach this message to it. Request"+
							" information: UUID = %s.", requestID)})
				}
			}()

			logger.Infow("request started",
				"requestID", requestID,
				"method", r.Method,
				"url", r.URL.Path,
			)

			next.ServeHTTP(crw, r.WithContext(ctx))

			logger.Infow("request completed",
				"requestID", requestID,
				"status", crw.statusCode,
				"duration", time.Since(start),
			)
		})
	}
}

type customResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (crw *customResponseWriter) WriteHeader(statusCode int) {
	crw.statusCode = statusCode
	crw.ResponseWriter.WriteHeader(statusCode)
}

// Middlewares -> recovery_and_logging
// -----------------------------------------------------------------------------------------------------------------------------------
// Responder

const jsonContentType = "application/json; charset=utf-8"

func JSON(w http.ResponseWriter, status int, v interface{}) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		jsonBytes = []byte(`{"message":"Failed to marshal response. Please report the issue to technical support and attach this message to it."}`)
	}

	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(status)
	_, _ = w.Write(jsonBytes)
}

func Send500(w http.ResponseWriter, logger *zap.SugaredLogger, err error, requestID string) {
	type response struct {
		Message string `json:"message"`
	}

	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "unknown"
		line = 0
	}
	location := fmt.Sprintf("%s : %d", file, line)

	logger.Errorw("unexpected error",
		"requestID", requestID,
		"error", err,
		"location", location,
	)
	JSON(w, http.StatusInternalServerError, response{
		fmt.Sprintf("Please report the issue to technical support and attach this message to it. Request"+
			" information: UUID = %s.", requestID)})
}

// Responder
// -----------------------------------------------------------------------------------------------------------------------------------
