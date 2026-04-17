package main

import (
	"log/slog"
	"os"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	slog.Info("NexusHub API starting", "version", "2.0.0-dev")
	// TODO: Initialize config, database, router, and start server
}
