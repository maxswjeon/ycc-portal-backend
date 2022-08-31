package groups

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

type AddGroupRequest struct {
	Name string `form:"name" json:"name" binding:"required"`
	Description string `form:"description" json:"description" binding:"required"`
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

	var request AddGroupRequest
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
	
	addRequest := ldap.NewAddRequest(fmt.Sprintf("cn=%s,ou=groups,%s", request.Name, os.Getenv("LDAP_BASE_DN")), nil)
	addRequest.Attribute("objectClass", []string{"top", "groupOfNames"})
	addRequest.Attribute("cn", []string{request.Name})
	addRequest.Attribute("member", []string{"cn=null,dc=ycc,dc=club"})
	addRequest.Attribute("description", []string{request.Description})
	err := conn.Add(addRequest)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to add group",
			"description": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
	})
}
