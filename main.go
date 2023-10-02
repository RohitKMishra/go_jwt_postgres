package main

import (
	"fmt"
	"log"

	"github.com/RohitKMishra/go_jwt_auth_server/controllers"
	"github.com/RohitKMishra/go_jwt_auth_server/initializers"
	"github.com/RohitKMishra/go_jwt_auth_server/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func Init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatalln("Failed to load environment variable \n", err.Error())
	}
	fmt.Println("Host", config.DBHost, "post ", config.DBPort, "name ", config.DBName, "user ", config.DBUser, "password ", config.DBPassword)
	initializers.ConnectDB(&config)
}

func main() {

	app := fiber.New()
	micro := fiber.New()
	Init()

	app.Mount("/api", micro)
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000",
		AllowHeaders:     "Origins, Content-Type, Accept",
		AllowMethods:     "GET, POST",
		AllowCredentials: true,
	}))

	micro.Route("/auth", func(router fiber.Router) {
		router.Post("/register", controllers.SignUpUser)
		router.Post("/login", controllers.SignInUser)
		router.Get("/logout", middleware.DeserializeUser, controllers.LogoutUser)
	})

	micro.Get("/user/me", middleware.DeserializeUser, controllers.GetMe)
	micro.Get("/api/healthchecker", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(&fiber.Map{
			"status":  "success",
			"message": "Welcome to golang, fiber and gorm",
		})
	})

	micro.All("*", func(c *fiber.Ctx) error {
		path := c.Path()
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "fail",
			"message": fmt.Sprintf("Path: %v does not exist on this server", path),
		})

	})

	log.Fatal(app.Listen(":8000"))
}
