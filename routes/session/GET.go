package session

import (
	"context"
	"lmm_backend/utils"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func GET(c *gin.Context) {
	session := sessions.Default(c)

	rawToken := session.Get("oauth2_token")

	if rawToken == nil {
		c.JSON(http.StatusOK, gin.H{
			"result": true,
			"status": false,
		})
		return
	}

	token := rawToken.(oauth2.Token)

	if token.Valid() {
		c.JSON(http.StatusOK, gin.H{
			"result": true,
			"status": true,
		})
		return
	}

	_, config, _, err := utils.GenerateOIDCConfig()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to create OIDC provider",
		})
		return
	}

	newToken, err := config.Client(context.Background(), &token).Transport.(*oauth2.Transport).Source.Token()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to refresh token",
		})
		return
	}

	session.Set("oauth2_token", *newToken)
	session.Save()

	c.JSON(http.StatusOK, gin.H{
		"result": true,
		"status": newToken.Valid(),
	})
}
