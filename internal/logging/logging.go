package logging

import (
	"context"
	"os"
	"path"

	"go.uber.org/zap"
)

type loggerKeyType int

const loggerKey loggerKeyType = iota
const TimestampField string = "ts"

var logger *zap.Logger

func init() {
	// a fallback/root logger for events without context
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	logger = logger.With(
		zap.Int("pid", os.Getpid()),
		zap.String("exe", path.Base(os.Args[0])),
	)
}

func DefaultLogger() *zap.Logger {
	return logger
}

func With(fields ...zap.Field) *zap.Logger {
	return logger.With(fields...)
}

func NewContext(ctx context.Context, fields ...zap.Field) context.Context {
	return context.WithValue(ctx, loggerKey, FromContext(ctx).With(fields...))
}

// WithContext returns a logger with as much context as possible
func FromContext(ctx context.Context) *zap.Logger {
	if ctx == nil {
		return logger
	}
	if ctxLogger, ok := ctx.Value(loggerKey).(*zap.Logger); ok {
		return ctxLogger
	} else {
		return logger
	}
}
