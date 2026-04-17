// Package handler holds HTTP handlers mounted on the Gin router. Handlers
// depend on repositories and services via plain struct fields — no
// framework-level DI.
package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/apierror"
)

func writeError(c *gin.Context, status int, code, msg string) {
	apierror.Write(c, status, code, msg)
}
