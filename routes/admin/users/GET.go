package user

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

	// TODO: Check forbidden
	
	conn, err := utils.LDAPConnectAndBind(os.Getenv("LDAP_BIND_DN"), os.Getenv("LDAP_BIND_PW"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to connect to LDAP",
		})
		return
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 
		0, // SizeLimit
		30, // TimeLimit 
		false, // TypesOnly
		"(&(objectClass=student)(uid=*))",
		[]string{"*"},
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

	var users []utils.User
	for _, entry := range result.Entries {
		uidNumber, err := strconv.Atoi(entry.GetAttributeValue("uidNumber"))
		if err != nil {
			uidNumber = -1
		}

		user := utils.User{
			DN: entry.DN,
			Uid: entry.GetAttributeValue("uid"),
			Cn: entry.GetAttributeValue("cn"),
			Sn: entry.GetAttributeValue("sn"),
			Gn: entry.GetAttributeValue("givenName"),
			Mail: entry.GetAttributeValue("mail"),
			UidNumber: uidNumber,
		}

		users = append(users, user)
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
		"data": users,
	})
}
