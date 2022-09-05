package routes

import (
	admin_group "lmm_backend/routes/admin/group"
	admin_groups_users "lmm_backend/routes/admin/group/users"
	admin_groups "lmm_backend/routes/admin/groups"
	admin_user "lmm_backend/routes/admin/user"
	admin_users "lmm_backend/routes/admin/users"
	admin_users_file "lmm_backend/routes/admin/users/file"
	login_callback "lmm_backend/routes/login/callback"
	login_start "lmm_backend/routes/login/start"
	session "lmm_backend/routes/session"
	user "lmm_backend/routes/user"
	user_detail "lmm_backend/routes/user/detail"
	user_password "lmm_backend/routes/user/password"

	"github.com/gin-gonic/gin"
)

func Apply(engine *gin.Engine) {
	engine.GET("/login/start", login_start.GET)
	engine.GET("/login/callback", login_callback.GET)
	engine.POST("/logout", session.DELETE)

	engine.GET("/session", session.GET)
	engine.DELETE("/session", session.DELETE)

	engine.GET("/user", user.GET)

	engine.GET("/user/detail", user_detail.GET)
	engine.POST("/user/password", user_password.POST)

	engine.GET("/admin/user/:dn", admin_user.GET)
	engine.PATCH("/admin/user/:dn", admin_user.PATCH)
	engine.DELETE("/admin/user/:dn", admin_user.DELETE)

	engine.GET("/admin/users", admin_users.GET)
	engine.POST("/admin/users", admin_users.POST)
	engine.POST("/admin/users/file", admin_users_file.POST)

	engine.DELETE("/admin/group/:dn", admin_group.DELETE)

	engine.GET("/admin/groups", admin_groups.GET)
	engine.POST("/admin/groups", admin_groups.POST)
	engine.POST("/admin/groups/:group/users", admin_groups_users.POST)
	engine.DELETE("/admin/groups/:group/users/:user", admin_groups_users.DELETE)
}
