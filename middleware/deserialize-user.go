package middleware

import (
	"fmt"
	"strings"

	"github.com/RohitKMishra/go_jwt_auth_server/initializers"
	"github.com/RohitKMishra/go_jwt_auth_server/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func DeserializeUser(c *fiber.Ctx) error {

	var tokenString string
	authorization := c.Get("Authorization")

	if strings.HasPrefix(authorization, "Bearer ") {
		tokenString = strings.TrimPrefix(authorization, "Bearer ")

	} else if c.Cookies("token") != "" {
		tokenString = c.Cookies("token")
	}
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "fail",
			"message": "You are not logged in",
		})
	}

	config, _ := initializers.LoadConfig(".")

	tokenByte, err := jwt.Parse((tokenString), func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", jwtToken.Header["alg"])
		}
		return []byte(config.JwtSecret), nil
	})

	// newToken, err := ObtainNewToken()

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "fail",
			"message": fmt.Sprintf("Invalidate token: %v", err),
		})
	}
	fmt.Println("token byte: ", tokenByte.Valid)

	claims, ok := tokenByte.Claims.(jwt.MapClaims)
	if !ok || !tokenByte.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "fail",
			"message": "Invalid token claim",
		})
	}

	var user models.User
	initializers.DB.First(&user, "id=?", fmt.Sprint(claims["sub"]))

	fmt.Println("user id", user)

	if user.ID.String() != claims["sub"] {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "fail",
			"message": "the user belonging to this token no longer exists",
		})
	}

	c.Locals("user", models.FilterUserRecord(&user))
	return c.Next()

}

// Middleware function to handle authenticated routes
func AuthMiddleware() func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		// Get the token from the "Authorization" header
		tokenString := c.Get("Authorization")
		config, _ := initializers.LoadConfig(".")
		secretKey := config.JwtSecret
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		}

		if tokenString == "" {
			// Token is missing; return an unauthorized response
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Token missing",
			})
		}

		fmt.Println("token string :", tokenString)
		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify the signing method and provide the key for validation
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return secretKey, nil
		})

		if err != nil {
			// Token parsing or validation error; return an unauthorized response
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Token parsing error",
			})
		}

		if !token.Valid {
			// Token is not valid; return an unauthorized response
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Token invalid",
			})
		}

		// Token is valid; continue to the next middleware or route handler
		return c.Next()
	}
}
