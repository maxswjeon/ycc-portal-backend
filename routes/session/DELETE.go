package session

import (
  "net/http"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
)

func DELETE(c *gin.Context) {
  session := sessions.Default(c)

  session.Clear()
  session.Save()

  c.JSON(http.StatusOK, gin.H{
    "result": true,
  })
}
