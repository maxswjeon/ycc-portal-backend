package user

import (
	"lmm_backend/utils"
	"net/http"
	"strconv"
	"strings"

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

	dn := c.Param("dn")
	if dn == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"result": false,
			"error":  "Bad Request - No dn provided",
		})
		return
	}

	conn := c.MustGet("ldap").(*ldap.Conn)

	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,     // SizeLimit
		30,    // TimeLimit
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
			"detail": err.Error(),
		})
		return
	}

	var users []utils.User
	for _, entry := range result.Entries {
		uidNumber, err := strconv.Atoi(entry.GetAttributeValue("uidNumber"))
		if err != nil {
			uidNumber = -1
		}

		studentEnrolled, err := strconv.ParseBool(entry.GetAttributeValue("studentEnrolled"))
		if err != nil {
			studentEnrolled = false
		}

		studentGraduated, err := strconv.ParseBool(entry.GetAttributeValue("studentGraduated"))
		if err != nil {
			studentGraduated = false
		}

		studentMajors := strings.Join(entry.GetAttributeValues("studentMajor"), ",")

		user := utils.User{
			DN:        entry.DN,
			Cn:        entry.GetAttributeValue("cn"),
			Gn:				 entry.GetAttributeValue("givenName"),
			Sn: 			 entry.GetAttributeValue("sn"),
			Uid:       entry.GetAttributeValue("uid"),
			Mail:      entry.GetAttributeValue("studentEmail"),
			UidNumber: uidNumber,
			StudentGender: entry.GetAttributeValue("studentGender"),
			StudentBirthday: entry.GetAttributeValue("studentBirthday"),
			TelephoneNumber: entry.GetAttributeValue("telephoneNumber"),
			StudentColleage: entry.GetAttributeValue("studentColleage"),
			StudentFirstMajor: entry.GetAttributeValue("studentFirstMajor"),
			StudentMajor: studentMajors,
			StudentEnrolled: studentEnrolled,
			StudentGraduated: studentGraduated,
		}

		users = append(users, user)
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
		"user":   users[0],
	})
}
