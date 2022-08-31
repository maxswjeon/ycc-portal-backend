package user

import (
	"lmm_backend/utils"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

func PATCH(c *gin.Context) {
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
	
	var user utils.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.AbortWithStatusJSON(400, gin.H{
			"result": false,
			"error":  err.Error(),
		})
		return
	}

	conn := c.MustGet("ldap").(*ldap.Conn)

	dn := c.Param("dn")
	modifyRequest := ldap.NewModifyRequest(dn, nil)
	modifyRequest.Replace("cn", []string{user.Sn + user.Gn})
	modifyRequest.Replace("sn", []string{user.Sn})
	modifyRequest.Replace("givenName", []string{user.Gn})
	modifyRequest.Replace("uid", []string{user.Uid})
	modifyRequest.Replace("mail", []string{user.Uid + "@" + os.Getenv("DOMAIN")})
	modifyRequest.Replace("uidNumber", []string{strconv.Itoa(user.UidNumber)})
	modifyRequest.Replace("telephoneNumber", []string{user.TelephoneNumber})
	modifyRequest.Replace("studentBirthday", []string{user.StudentBirthday})
	modifyRequest.Replace("studentColleage", []string{user.StudentColleage})
	modifyRequest.Replace("studentFirstMajor", []string{strings.Split(user.StudentMajor, ",")[0]})
	modifyRequest.Replace("studentMajor", strings.Split(user.StudentMajor, ","))
	modifyRequest.Replace("studentEmail", strings.Split(user.Mail, " "))
	modifyRequest.Replace("studentGender", []string{user.StudentGender})
	modifyRequest.Replace("studentEnrolled", []string{strings.ToUpper(strconv.FormatBool(user.StudentEnrolled))})
	modifyRequest.Replace("studentGraduated", []string{strings.ToUpper(strconv.FormatBool(user.StudentGraduated))})

	if err := conn.Modify(modifyRequest); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to modify user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
	})
}
