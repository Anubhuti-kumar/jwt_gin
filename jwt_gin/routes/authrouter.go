package routes

import (
	controller "jwt_gin/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("user/signup", controller.Signup())
	incomingRoutes.POST("user/login", controller.Login())
}
