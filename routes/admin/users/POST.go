package users

import (
	"lmm_backend/utils"
	"log"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

type NewUserRequest struct {
	Uid       string `form:"uid" json:"uid" binding:"required"`
	Sn        string `form:"sn" json:"sn" binding:"required"`
	Gn        string `form:"gn" json:"gn" binding:"required"`
	UidNumber string `form:"uidNumber" json:"uidNumber" binding:"required"`
	Mail      string `form:"mail" json:"mail" binding:"required"`
	Birthday  string `form:"studentBirthday" json:"studentBirthday" binding:"required"`
	TelephoneNumber string `form:"telephoneNumber" json:"telephoneNumber" binding:"required"`
	Gender    string `form:"studentGender" json:"studentGender" binding:"required"`
	Colleage  string `form:"studentColleage" json:"studentColleage" binding:"required"`
	Majors    string `form:"studentMajor" json:"studentMajor" binding:"required"`
	Enrolled  *bool  `form:"studentEnrolled" json:"studentEnrolled" binding:"required"`
	Graduated *bool  `form:"studentGraduated" json:"studentGraduated" binding:"required"`
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

	conn := c.MustGet("ldap").(*ldap.Conn)

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

	err := utils.LDAPAddUser(conn, request.Uid, request.Sn, request.Gn, request.UidNumber, request.TelephoneNumber, request.Mail, request.Birthday, request.Gender, request.Colleage, request.Majors, *request.Enrolled, *request.Graduated, password, hash)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to add user to LDAP",
		})
		return
	}

	err = utils.SendInitialPasswordMail(strings.Split(request.Mail, " ")[0], request.Uid, password)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to send initial password mail",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
	})
}
