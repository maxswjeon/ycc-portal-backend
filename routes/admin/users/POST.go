package user

import (
	"lmm_backend/utils"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

type NewUserRequest struct {
	Uid string `form:"username" json:"username" binding:"required"`
	Sn string `form:"lastname" json:"lastname" binding:"required"`
	Gn string `form:"firstname" json:"firstname" binding:"required"`
	UidNumber *int `form:"student_number" json:"student_number" binding:"required"`
	Mail string `form:"email" json:"email" binding:"required"`
	Birthday string `form:"birthday" json:"birthday" binding:"required"`
	Gender string `form:"gender" json:"gender" binding:"required"`
	Colleage string `form:"colleage" json:"colleage" binding:"required"`
	Majors string `form:"majors" json:"majors" binding:"required"`
	Enrolled *bool `form:"enrolled" json:"enrolled" binding:"required"`
	Graduated *bool `form:"graduated" json:"graduated" binding:"required"`
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

	conn, err := utils.LDAPConnectAndBind(os.Getenv("LDAP_BIND_DN"), os.Getenv("LDAP_BIND_PW"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to connect to LDAP",
		})
		return
	}

	var request NewUserRequest	
	if err := c.ShouldBind(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"result": false,
			"error":  "Bad request",
		})
		log.Print(err)
		return
	}

	password, hash := utils.LDAPGeneratePassword()

	addRequest := ldap.NewAddRequest("uid=" + request.Uid + ",ou=people," + os.Getenv("LDAP_BASE_DN"), nil)
	addRequest.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "student", "PostfixBookMailAccount"})
	addRequest.Attribute("cn", []string{request.Sn + request.Gn})
	addRequest.Attribute("sn", []string{request.Sn})
	addRequest.Attribute("givenName", []string{request.Gn})
	addRequest.Attribute("uid", []string{request.Uid})
	addRequest.Attribute("mail", []string{request.Uid + "@" + os.Getenv("DOMAIN")})
	addRequest.Attribute("uidNumber", []string{strconv.Itoa(*request.UidNumber)})
	addRequest.Attribute("studentBirthday", []string{request.Birthday})
	addRequest.Attribute("studentColleage", []string{request.Colleage})
	addRequest.Attribute("studentFirstMajor", []string{strings.Split(request.Majors, ",")[0]})	
	addRequest.Attribute("studentMajor", strings.Split(request.Majors, ","))
	addRequest.Attribute("studentEmail", strings.Split(request.Mail, " "))
	addRequest.Attribute("studentGender", []string{request.Gender})
	addRequest.Attribute("studentEnrolled", []string{strings.ToUpper(strconv.FormatBool(*request.Enrolled))})
	addRequest.Attribute("studentGraduated", []string{strings.ToUpper(strconv.FormatBool(*request.Graduated))})
	addRequest.Attribute("userPassword", []string{hash})

	if err := conn.Add(addRequest); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to add user",
		})
		return
	}

	err = utils.SendInitialPasswordMail(strings.Split(request.Mail, " ")[0], request.Uid, password)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to send initial password mail",
		})

		log.Print(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
	})
}
