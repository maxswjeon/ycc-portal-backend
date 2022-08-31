package groups

import (
	"lmm_backend/utils"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

func GET(c *gin.Context) {
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

	connRaw := c.MustGet("ldap")
	if connRaw == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Internal Server Error - No LDAP connection",
		})
		return
	}

	conn := connRaw.(*ldap.Conn)

	result, err := utils.LDAPGetGroups(conn)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Internal Server Error - LDAP Query Error",
		})
		return
	}

	var groupsData []utils.Group
	for _, entry := range result.Entries {
		group := utils.Group{
			DN:  entry.DN,
			Cn: entry.GetAttributeValue("cn"),
			Description: entry.GetAttributeValue("description"),
			Members: entry.GetAttributeValues("member"),
		}

		groupsData = append(groupsData, group)
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
		"groups": groupsData,
	})
}
