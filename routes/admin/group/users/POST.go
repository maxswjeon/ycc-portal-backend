package users

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

type AddUserToGroupRequest struct {
	UserDN string `form:"dn" json:"dn" binding:"required"`
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

	groups := session.Get("groups")
	if groups == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"result": false,
			"error":  "Unauthorized - No Group session set",
		})
		return
	}

	isAdmin := false
	for _, group := range groups.([]string) {
		if group == "admin" {
			isAdmin = true
			break
		}
	}

	if !isAdmin {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"result": false,
			"error":  "Forbidden - Not an admin",
		})
		return
	}

	var request AddUserToGroupRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"result": false,
			"error": "Bad Request",
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
	groupDN := c.Param("group")

	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Add("member", []string{request.UserDN})
	err := conn.Modify(modifyRequest)
	
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Internal Server Error - Failed to add user to group",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
	})
}
