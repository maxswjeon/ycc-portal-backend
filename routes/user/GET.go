package info

import (
	"context"
	"lmm_backend/utils"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// GET /user/info
// Get current user info
func GET(c *gin.Context) {
	session := sessions.Default(c)

	if session.Get("authorized") == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"result": false,
			"error":  "Unauthorized",
		})
		return
	}

	provider, _, _, err := utils.GenerateOIDCConfig()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to load OIDC Config",
		})
		return
	}

	token := session.Get("oauth2_token").(oauth2.Token)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to load token",
		})
		return
	}

	userInfo, err := provider.UserInfo(context.Background(), oauth2.StaticTokenSource(&token))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to load user info",
		})
		return
	}

	var claims struct {
		SurName       string   `json:"family_name"`
		GivenName     string   `json:"given_name"`
		Username      string   `json:"preferred_username"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Groups        []string `json:"groups"`
	}

	var claims_restructed struct {
		Name          string   `json:"name"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"verified"`
		UserName      string   `json:"username"`
		Groups        []string `json:"groups"`
	}

	err = userInfo.Claims(&claims)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to unmarshal user info",
		})
		return
	}

	claims_restructed.Name = claims.SurName + claims.GivenName
	claims_restructed.Email = claims.Email
	claims_restructed.EmailVerified = claims.EmailVerified
	claims_restructed.UserName = claims.Username
	claims_restructed.Groups = claims.Groups

	c.JSON(http.StatusOK, gin.H{
		"result": true,
		"data":   claims_restructed,
	})
}
