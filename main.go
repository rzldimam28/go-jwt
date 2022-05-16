package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type Credentials struct {
	Id int `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var user = Credentials{
	Id: 1,
	Username: "rzldimam",
	Password: "my-password",
}

func CreateResponse(code int, data interface{}) gin.H {
	return gin.H{
		"code": code,
		"data": data,
	}
}

func main() {
	router := gin.Default()

	router.GET("/", HomeHandler)
	router.GET("/secret", Auth, SecretHandler)
	router.POST("/login", LoginHandler)

	log.Fatal(router.Run("localhost:8080"))
}

func HomeHandler(c *gin.Context) {
	c.String(http.StatusOK, "Home Page")
}

func SecretHandler(c *gin.Context) {
	c.String(http.StatusOK, "Super Secret Information")
}

func LoginHandler(c *gin.Context) {
	var u Credentials
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, CreateResponse(422, "can not process request"))
		return
	}
	if u.Username != user.Username || u.Password != user.Password {
		c.JSON(http.StatusUnauthorized, CreateResponse(401, "Unaouthorized"))
		return
	}
	token, err := GenerateToken(u.Username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, CreateResponse(422, err.Error()))
	}
	c.JSON(http.StatusCreated, CreateResponse(201, token))
}

func GenerateToken(username string) (string, error) {
	sign := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := sign.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["user"] = username
	claims["exp"] = time.Now().Add(time.Minute * 5).Unix()

	token, err := sign.SignedString([]byte("secret-key"))
	if err != nil {
		return "", errors.New("can not generate token")
	}
	return token, nil
}

func Auth(c *gin.Context) {
	tokenString := c.Request.Header.Get("auth")
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.GetSigningMethod("HS256") {
			return nil, errors.New("unexpected signing method")
		}
		return []byte("secret-key"), nil
	})
	if token != nil && err == nil {
		return
	} else {
		c.JSON(http.StatusUnauthorized, CreateResponse(401, "unauthorized"))
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}