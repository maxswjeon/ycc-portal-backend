package routes

import (
	admin_user "lmm_backend/routes/admin/user"
	admin_users "lmm_backend/routes/admin/users"
	login_callback "lmm_backend/routes/login/callback"
	login_start "lmm_backend/routes/login/start"
	session "lmm_backend/routes/session"
	user "lmm_backend/routes/user"

	"github.com/gin-gonic/gin"
)

func Apply(engine *gin.Engine) {
  engine.GET("/login/start", login_start.GET)
  engine.GET("/login/callback", login_callback.GET)
  engine.POST("/logout", session.DELETE)

  engine.GET("/session", session.GET)
  engine.DELETE("/session", session.DELETE)

  engine.GET("/user", user.GET)

  engine.GET("/admin/user/:id", admin_user.GET)
  engine.GET("/admin/users", admin_users.GET)
  engine.POST("/admin/users", admin_users.POST)
}
