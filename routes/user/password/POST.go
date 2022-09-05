package password

import (
	"context"
	"lmm_backend/utils"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/oauth2"
)

type PasswordChangeRequest struct {
	OldPassword string `form:"old_password" json:"old_password" binding:"required"`
	Password    string `form:"new_password" json:"new_password" binding:"required"`
}

func POST(c *gin.Context) {
	session := sessions.Default(c)

	if session.Get("authorized") == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"result": false,
			"error":  "Unauthorized",
		})
		return
	}

	var request PasswordChangeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"result": false,
			"error":  "Bad Request",
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

	err = userInfo.Claims(&claims)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to unmarshal user info",
		})
		return
	}

	connRaw := c.MustGet("ldap")
	if connRaw == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Internal Server Error - No LDAP connection",
		})
		return
	}
	conn := connRaw.(*ldap.Conn)
	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,     // SizeLimit
		0,     // TimeLimit
		false, // TypesOnly
		"(&(objectClass=person)(uid="+claims.Username+"))",
		[]string{"*"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to search LDAP",
			"detail": err.Error(),
		})
		return
	}

	if len(result.Entries) == 0 {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"result": false,
			"error":  "User not found",
		})
		return
	}

	if len(result.Entries) > 1 {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to search LDAP - Multiple users found",
		})
		return
	}

	entry := result.Entries[0]

	encoder := utils.SSHAEncoder{}

	ok, err := encoder.Verify([]byte(request.OldPassword), entry.GetAttributeValue("userPassword"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to verify password with Internal Server Error",
			"detail": err.Error(),
		})
		return
	}

	if !ok {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"result": false,
			"error":  "Old password is incorrect",
		})
		return
	}

	hash := encoder.Encode([]byte(request.Password))

	modifyRequest := ldap.NewModifyRequest(entry.DN, nil)
	modifyRequest.Replace("userPassword", []string{hash})
	modifyRequest.Replace("sambaNTPassword", []string{"{nt}" + utils.NTLMHash(request.Password)})

	conn.Modify(modifyRequest)

	c.JSON(http.StatusOK, gin.H{
		"result": true,
	})
}
