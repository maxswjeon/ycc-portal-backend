package users

import (
	"lmm_backend/utils"
	"net/http"
	"os"
	"strconv"

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

	conn := c.MustGet("ldap").(*ldap.Conn)

	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,     // SizeLimit
		30,    // TimeLimit
		false, // TypesOnly
		"(&(objectClass=student)(uid=*))",
		[]string{"dn", "cn", "uid", "studentEmail", "uidNumber"},
		nil, // Controls
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to search LDAP",
		})
		return
	}

	var users []utils.UserSlim
	for _, entry := range result.Entries {
		uidNumber, err := strconv.Atoi(entry.GetAttributeValue("uidNumber"))
		if err != nil {
			uidNumber = -1
		}

		user := utils.UserSlim{
			DN:        entry.DN,
			Uid:       entry.GetAttributeValue("uid"),
			Cn:        entry.GetAttributeValue("cn"),
			Mail:      entry.GetAttributeValue("studentEmail"),
			UidNumber: uidNumber,
		}

		users = append(users, user)
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
		"data":   users,
	})
}
