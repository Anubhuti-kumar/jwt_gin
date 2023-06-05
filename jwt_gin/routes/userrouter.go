package routes

import (
	controller "jwt_gin/controllers"
	middleware "jwt_gin/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	// Authentication is Used because at this time we need token
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.POST("/users/:user_id", controller.GetUser())
}
