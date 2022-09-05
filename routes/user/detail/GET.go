package detail

import (
	"context"
	"lmm_backend/utils"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/oauth2"
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

	connRaw := c.MustGet("ldap")
	if connRaw == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Internal Server Error - No LDAP connection",
		})
		return
	}

	provider, _, _, err := utils.GenerateOIDCConfig()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to load OIDC Config",
		})
		return
	}

	token := session.Get("oauth2_token").(oauth2.Token)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to load token",
		})
		return
	}

	userInfo, err := provider.UserInfo(context.Background(), oauth2.StaticTokenSource(&token))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to load user info",
		})
		return
	}

	var claims struct {
		SurName       string   `json:"family_name"`
		GivenName     string   `json:"given_name"`
		Username      string   `json:"preferred_username"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Groups        []string `json:"groups"`
	}

	err = userInfo.Claims(&claims)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to unmarshal user info",
		})
		return
	}

	conn := connRaw.(*ldap.Conn)

	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,     // SizeLimit
		0,     // TimeLimit
		false, // TypesOnly
		"(&(objectClass=person)(uid="+claims.Username+"))",
		[]string{"*"},
		nil,
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

	if len(result.Entries) == 0 {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"result": false,
			"error":  "User not found",
		})
		return
	}

	if len(result.Entries) > 1 {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  "Failed to search LDAP - Multiple users found",
		})
		return
	}

	entry := result.Entries[0]

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
		DN:                entry.DN,
		Cn:                entry.GetAttributeValue("cn"),
		Gn:                entry.GetAttributeValue("givenName"),
		Sn:                entry.GetAttributeValue("sn"),
		Uid:               entry.GetAttributeValue("uid"),
		Mail:              entry.GetAttributeValue("studentEmail"),
		UidNumber:         uidNumber,
		StudentGender:     entry.GetAttributeValue("studentGender"),
		StudentBirthday:   entry.GetAttributeValue("studentBirthday"),
		TelephoneNumber:   entry.GetAttributeValue("telephoneNumber"),
		StudentColleage:   entry.GetAttributeValue("studentColleage"),
		StudentFirstMajor: entry.GetAttributeValue("studentFirstMajor"),
		StudentMajor:      studentMajors,
		StudentEnrolled:   studentEnrolled,
		StudentGraduated:  studentGraduated,
	}

	c.JSON(http.StatusOK, gin.H{
		"result": true,
		"user":   user,
	})
}
