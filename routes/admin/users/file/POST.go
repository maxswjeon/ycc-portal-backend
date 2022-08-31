package file

import (
	"lmm_backend/handlers"
	"lmm_backend/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)


func POST(c *gin.Context) {
	logData := []utils.Message{}

	connRaw := c.MustGet("ldap")
	if connRaw == nil {
		logData = append(logData, utils.Message{
			Type: "error",
			Message:  "No LDAP connection found",
		})
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"error":  logData,
		})
		return
	}

	conn := connRaw.(*ldap.Conn)	

	file, err := c.FormFile("file")
	if err != nil {
		logData = append(logData, utils.Message{
			Message: "No file found in request",
			Type: utils.ERROR,
		})
	
		c.AbortWithStatusJSON(400, gin.H{
			"result": false,
			"logs":  logData,
		})
		return
	}

	fileData, err := file.Open()
	defer fileData.Close()
	if err != nil {
		logData = append(logData, utils.Message{
			Message: "Error while reading file",
			Type: utils.ERROR,
		})

		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"result": false,
			"logs": logData,
		})
		return
	}

	if strings.HasSuffix(file.Filename, ".csv") {
		ok, logDataAdditional := handlers.CSV(conn, &fileData)
		logData = append(logData, logDataAdditional...)
		if !ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"result": false,
				"logs": logData,
			})
			return
		}
	} else {
		// Handle Error
		logData = append(logData, utils.Message{
			Message: "File is not a CSV",
			Type: utils.ERROR,
		})
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"result": false,
			"logs": logData,
		})
	}

	c.JSON(200, gin.H{
		"result": true,
		"logs": logData,
	})
}
