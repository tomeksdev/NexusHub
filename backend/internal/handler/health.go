package handler

import "github.com/gin-gonic/gin"

// Health is the liveness probe used by Docker, Kubernetes, and the install
// script. Does not touch the DB — for that we'll add /readyz later.
func Health(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}
