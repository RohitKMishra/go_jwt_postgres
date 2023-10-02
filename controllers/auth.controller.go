package controllers

import (
	"fmt"
	"strings"
	"time"

	"github.com/RohitKMishra/go_jwt_auth_server/initializers"
	"github.com/RohitKMishra/go_jwt_auth_server/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func SignUpUser(c *fiber.Ctx) error {
	var payload *models.SignUpInput

	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "fail",
			"message": err.Error(),
		})
	}
	newUUID := uuid.New()

	payload.ID = newUUID

	fmt.Println("Payload id: ", payload.ID, "payload name: ", payload.Name)

	errors := models.ValidateStruct(payload)
	if errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "fail",
			"errors": errors,
		})
	}

	if payload.Password != payload.PasswordConfirm {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "fail",
			"message": "Password did not match!",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "fail",
			"message": err.Error(),
		})
	}

	newUser := models.User{
		ID:       (*uuid.UUID)(&payload.ID),
		Name:     payload.Name,
		Email:    strings.ToLower(payload.Email),
		Password: string(hashedPassword),
		Photo:    &payload.Photo,
	}

	result := initializers.DB.Create(&newUser)

	if result.Error != nil && strings.Contains(result.Error.Error(), "duplicate key value voilates unique") {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"status":  "fail",
			"message": "User with that email already exists",
		})
	} else if result.Error != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"status":  "error",
			"message": "Something bad happened",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"data": fiber.Map{
			"user": models.FilterUserRecord(&newUser),
		},
	})
}

func SignInUser(c *fiber.Ctx) error {
	var payload *models.SignInInput
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "fail",
			"message": err.Error(),
		})
	}

	errors := models.ValidateStruct(payload)
	if errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errors)
	}

	var user models.User
	//result := initializers.DB.First(&user, "email=?", strings.ToLower(payload.Email))
	// result := initializers.DB.Where("email=?", payload.Email).First(&user)

	if err := initializers.DB.Where("email = ?", payload.Email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// User not found
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"message": "User not found",
			})
		}
		// Handle other database errors
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Database error",
		})
	}

	// result := user

	// if result.Error != nil {
	// 	c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
	// 		"status":  "fail",
	// 		"message": "Invalid email or password",
	// 	})
	// // }
	// c.Locals("email", payload.Email)
	// fmt.Println("Email :", payload)
	// fmt.Println("email ", c.Locals("email"))
	// fmt.Println("result :", result)

	// xType := reflect.TypeOf(payload)
	// fmt.Printf("Type of x: %s\n", xType)

	err := bcrypt.CompareHashAndPassword([]byte(user.Password),
		[]byte(payload.Password))

	if err != nil {
		c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "fail",
			"message": "Invalid email or password",
		})
	}

	config, _ := initializers.LoadConfig(".")

	tokenByte := jwt.New(jwt.SigningMethodHS256)

	expirationTime := time.Now().Add(24 * time.Hour)
	fmt.Println("expiration time ", expirationTime)

	now := time.Now().UTC()
	claims := tokenByte.Claims.(jwt.MapClaims)
	claims["sub"] = user.ID
	claims["exp"] = expirationTime.Unix()
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()

	tokenString, err := tokenByte.SignedString([]byte(config.JwtSecret))
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"status":  "fail",
			"message": fmt.Sprintf("Generating JWT token failed: %v", err),
		})
	}

	fmt.Println(IsTokenExpired(tokenString))

	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   config.JwtMaxAge,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "success",
		"token":  tokenString,
	})
}

func IsTokenExpired(tokenString string) (bool, error) {
	// Parse the token without verifying the signature
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return false, err
	}

	// Check if the token is valid
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Get the expiration time from the claims
		exp := int64(claims["exp"].(float64))
		fmt.Println("expiration time", exp)

		// Compare the expiration time with the current time
		currentTime := time.Now().Unix()
		return currentTime > exp, nil
	}

	// Token is invalid
	return false, nil
}

func LogoutUser(c *fiber.Ctx) error {
	expired := time.Now().Add(-time.Hour * 24)
	c.Cookie(&fiber.Cookie{
		Name:    "token",
		Value:   "",
		Expires: expired,
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "success",
	})
}

// func RefreshTokenHandler(c *fiber.Ctx) error {
// 	// Get the refresh token from the request header.
// 	refreshToken := c.Get("Authorization")

// 	// Verify the refresh token.
// 	claims, err := utils.VerifyRefreshToken(refreshToken)
// 	if err != nil {
// 		return c.SendStatus(401)
// 	}
// 	// Generate a new access token and refresh token.
// 	accessToken, newRefreshToken, err := utils.GenerateTokens(claims)
// 	if err != nil {
// 		return c.SendStatus(500)
// 	}

// 	// Set the new access token in the response header.
// 	c.Set("Authorization", "Bearer"+accessToken)

// 	// Return the new access token and refresh token to the client.
// 	return c.JSON(fiber.Map{
// 		"accessToken":  accessToken,
// 		"refreshToken": newRefreshToken,
// 	})

// }
