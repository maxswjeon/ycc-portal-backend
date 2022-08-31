package user

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

func DELETE(c *gin.Context) {
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

	dn := c.Param("dn")
	if dn == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"result": false,
			"error":  "Bad Request - No dn provided",
		})
		return
	}

	conn := c.MustGet("ldap").(*ldap.Conn)

	deleteRequest := ldap.NewDelRequest(dn, nil)
	err := conn.Del(deleteRequest)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to Delete Entry in LDAP",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
	})
}
