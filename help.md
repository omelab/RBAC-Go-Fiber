## Role-Based Access Control (RBAC) system in a Go project

Creating a Role-Based Access Control (RBAC) system in a Go project with Fiber, PostgreSQL, JWT for authentication, and GORM as the ORM with golang-migrate for migrations, inspired by Laravel's Spatie package, involves several steps. This will include setting up your project, designing your database schema, implementing middleware for access control, and creating necessary functions for managing roles and permissions.

### Project Structure

```bash
go-fiber-rbac
│
├── main.go
├── go.mod
├── go.sum
├── config
│   └── config.go
├── database
│   ├── migration
│   │   └── migrations.go
│   └── database.go
├── models
│   ├── user.go
│   ├── role.go
│   └── permission.go
├── controllers
│   ├── auth.go
│   ├── role.go
│   └── permission.go
├── middleware
│   └── auth.go
├── routes
│   └── routes.go
└── utils
    ├── jwt.go
    └── mail.go
```


### Step-by-Step Implementation

*** 1. Initialize the Project ***

```bash
mkdir go-fiber-rbac
cd go-fiber-rbac
go mod init go-fiber-rbac
```

*** 2. Install Dependencies ***

```bash
go get github.com/gofiber/fiber/v2
go get github.com/gofiber/jwt/v3
go get github.com/jackc/pgx/v4
go get github.com/jinzhu/gorm
go get github.com/golang-migrate/migrate/v4
go get github.com/dgrijalva/jwt-go
go get github.com/joho/godotenv
```

*** 3. Create Configuration File ***
Create `config/config.go` to load environment variables:

```go
package config

import (
    "log"
    "os"
    "github.com/joho/godotenv"
)

func LoadConfig() {
    err := godotenv.Load()
    if err != nil {
        log.Fatalf("Error loading .env file")
    }
}
```

Create a `.env` file in the root directory:

```makefile
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_user
DB_PASS=your_password
DB_NAME=your_db
JWT_SECRET=your_secret_key

SMTP_HOST=smtp.example.com
SMTP_USER=your_email@example.com
SMTP_PASS=your_password
SMTP_FROM=your_email@example.com
```

*** 4. Set Up Database and Migrations ***
Create database/database.go to initialize the database:

```go
package database

import (
    "fmt"
    "log"
    "os"

    "github.com/jinzhu/gorm"
    _ "github.com/jinzhu/gorm/dialects/postgres"
    "go-fiber-rbac/models"
)

var DB *gorm.DB

func Connect() {
    var err error
    DB, err = gorm.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
        os.Getenv("DB_HOST"),
        os.Getenv("DB_PORT"),
        os.Getenv("DB_USER"),
        os.Getenv("DB_NAME"),
        os.Getenv("DB_PASS"),
    ))
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }
}

func Migrate() {
    DB.AutoMigrate(&models.User{}, &models.Role{}, &models.Permission{})
}
```

Create `database/migration/migrations.go`:

```go
package migration

import "go-fiber-rbac/database"

func RunMigrations() {
    database.Migrate()
}
```

*** 5. Create Models ***

Create `models/user.go`:

```go
package models

import "github.com/jinzhu/gorm"

type User struct {
    gorm.Model
    Username       string `gorm:"unique"`
    Password       string
    Email          string `gorm:"unique"`
    EmailVerified  bool
    VerificationToken string
    Roles          []Role `gorm:"many2many:user_roles;"`
}
```

Create `models/role.go`:

```go
package models

import "github.com/jinzhu/gorm"

type Role struct {
    gorm.Model
    Name        string       `gorm:"unique"`
    Permissions []Permission `gorm:"many2many:role_permissions;"`
}
```

Create `models/permission.go`:

```go
package models

import "github.com/jinzhu/gorm"

type Permission struct {
    gorm.Model
    Name string `gorm:"unique"`
}
```

*** 6. Create Controllers ***

Create `controllers/auth.go`:

```go
package controllers

import (
    "github.com/gofiber/fiber/v2"
    "github.com/dgrijalva/jwt-go"
    "golang.org/x/crypto/bcrypt"
    "go-fiber-rbac/database"
    "go-fiber-rbac/models"
    "go-fiber-rbac/utils"
    "os"
    "time"
    "crypto/rand"
    "encoding/hex"
    "log"
)

func generateVerificationToken() (string, error) {
    token := make([]byte, 16)
    _, err := rand.Read(token)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(token), nil
}

func Register(c *fiber.Ctx) error {
    type RegisterInput struct {
        Username string `json:"username"`
        Password string `json:"password"`
        Email    string `json:"email"`
    }

    var input RegisterInput
    if err := c.BodyParser(&input); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
    }

    verificationToken, err := generateVerificationToken()
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate verification token"})
    }

    user := models.User{
        Username:          input.Username,
        Password:          string(hashedPassword),
        Email:             input.Email,
        EmailVerified:     false,
        VerificationToken: verificationToken,
    }

    if err := database.DB.Create(&user).Error; err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
    }

    // Assign default role
    var role models.Role
    if err := database.DB.Where("name = ?", "user").First(&role).Error; err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Default role not found"})
    }

    database.DB.Model(&user).Association("Roles").Append(&role)

    // Send verification email
    err = utils.SendVerificationEmail(user.Email, verificationToken)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send verification email"})
    }

    return c.JSON(fiber.Map{"message": "User registered successfully. Please check your email for verification."})
}

func VerifyEmail(c *fiber.Ctx) error {
    token := c.Params("token")
    var user models.User

    if err := database.DB.Where("verification_token = ?", token).First(&user).Error; err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid token"})
    }

    user.EmailVerified = true
    user.VerificationToken = ""

    if err := database.DB.Save(&user).Error; err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to verify email"})
    }

    return c.JSON(fiber.Map{"message": "Email verified successfully"})
}

func Login(c *fiber.Ctx) error {
    type LoginInput struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    var input LoginInput
    if err := c.BodyParser(&input); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
    }

    var user models.User
    if err := database.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
    }

    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
    }

    if !user.EmailVerified {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Email not verified"})
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": user.ID,
        "exp":     time.Now().Add(time.Hour * 72).Unix(),
    })

    tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not log in"})
    }

    return c.JSON(fiber.Map{"token": tokenString})
}
```

Create `controllers/role.go` for CRUD operations:

```go
package controllers

import (
    "github.com/gofiber/fiber/v2"
    "go-fiber-rbac/database"
    "go-fiber-rbac/models"
)

func CreateRole(c *fiber.Ctx) error {
    var role models.Role
    if err := c.BodyParser(&role); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
    }

    if err := database.DB.Create(&role).Error; err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create role"})
    }

    return c.JSON(role)
}

func GetRoles(c *fiber.Ctx) error {
    var roles []models.Role
    database.DB.Find(&roles)
    return c.JSON(roles)
}

func UpdateRole(c *fiber.Ctx) error {
    id := c.Params("id")
    var role models.Role

    if err := database.DB.First(&role, id).Error; err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Role not found"})
    }

    if err := c.BodyParser(&role); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
    }

    database.DB.Save(&role)
    return c.JSON(role)
}

func DeleteRole(c *fiber.Ctx) error {
    id := c.Params("id")
    var role models.Role

    if err := database.DB.First(&role, id).Error; err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Role not found"})
    }

    database.DB.Delete(&role)
    return c.SendStatus(fiber.StatusNoContent)
}
```

Create `controllers/permission.go` for CRUD operations:

```go
package controllers

import (
    "github.com/gofiber/fiber/v2"
    "go-fiber-rbac/database"
    "go-fiber-rbac/models"
)

func CreatePermission(c *fiber.Ctx) error {
    var permission models.Permission
    if err := c.BodyParser(&permission); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
    }

    if err := database.DB.Create(&permission).Error; err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create permission"})
    }

    return c.JSON(permission)
}

func GetPermissions(c *fiber.Ctx) error {
    var permissions []models.Permission
    database.DB.Find(&permissions)
    return c.JSON(permissions)
}

func UpdatePermission(c *fiber.Ctx) error {
    id := c.Params("id")
    var permission models.Permission

    if err := database.DB.First(&permission, id).Error; err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Permission not found"})
    }

    if err := c.BodyParser(&permission); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
    }

    database.DB.Save(&permission)
    return c.JSON(permission)
}

func DeletePermission(c *fiber.Ctx) error {
    id := c.Params("id")
    var permission models.Permission

    if err := database.DB.First(&permission, id).Error; err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Permission not found"})
    }

    database.DB.Delete(&permission)
    return c.SendStatus(fiber.StatusNoContent)
}
```

*** 7. Utility for Sending Emails ***

Create `utils/mail.go` to handle email sending. Here, I'll use a simple example with SMTP.

```go
package utils

import (
    "gopkg.in/gomail.v2"
    "os"
)

func SendVerificationEmail(to string, token string) error {
    m := gomail.NewMessage()
    m.SetHeader("From", os.Getenv("SMTP_FROM"))
    m.SetHeader("To", to)
    m.SetHeader("Subject", "Verify your email")
    m.SetBody("text/html", "Please verify your email by clicking the link: <a href=\"http://localhost:3000/verify/"+token+"\">Verify Email</a>")

    d := gomail.NewDialer(
        os.Getenv("SMTP_HOST"),
        587,
        os.Getenv("SMTP_USER"),
        os.Getenv("SMTP_PASS"),
    )

    return d.DialAndSend(m)
}
```

*** 8. Create Middleware ***

Create `middleware/auth.go`:

```go
package middleware

import (
    "strings"
    "github.com/gofiber/fiber/v2"
    "github.com/dgrijalva/jwt-go"
    "go-fiber-rbac/database"
    "go-fiber-rbac/models"
    "os"
)

func AuthMiddleware() fiber.Handler {
    return func(c *fiber.Ctx) error {
        tokenString := c.Get("Authorization")
        if tokenString == "" {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "No token provided"})
        }

        tokenString = strings.TrimPrefix(tokenString, "Bearer ")

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("JWT_SECRET")), nil
        })
        if err != nil || !token.Valid {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
        }

        claims := token.Claims.(jwt.MapClaims)
        userID := claims["user_id"].(float64)

        var user models.User
        if err := database.DB.First(&user, int(userID)).Error; err != nil {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid user"})
        }

        c.Locals("user", user)
        return c.Next()
    }
}
```

*** 8. Create Utility for JWT ***

Create `utils/jwt.go`:

```go
package utils

import (
    "github.com/dgrijalva/jwt-go"
    "os"
    "time"
)

func GenerateToken(userID uint) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(time.Hour * 72).Unix(),
    })

    return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
```

*** 9. Define Routes ***

Create `routes/routes.go`:

```go
package routes

import (
    "github.com/gofiber/fiber/v2"
    "go-fiber-rbac/controllers"
    "go-fiber-rbac/middleware"
)

func Setup(app *fiber.App) {
    app.Post("/login", controllers.Login)
    app.Post("/register", controllers.Register)
    app.Get("/verify/:token", controllers.VerifyEmail)

    admin := app.Group("/admin", middleware.AuthMiddleware())
    admin.Get("/", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"message": "Welcome, Admin!"})
    })

    admin.Post("/roles", controllers.CreateRole)
    admin.Get("/roles", controllers.GetRoles)
    admin.Put("/roles/:id", controllers.UpdateRole)
    admin.Delete("/roles/:id", controllers.DeleteRole)

    admin.Post("/permissions", controllers.CreatePermission)
    admin.Get("/permissions", controllers.GetPermissions)
    admin.Put("/permissions/:id", controllers.UpdatePermission)
    admin.Delete("/permissions/:id", controllers.DeletePermission)
}
```


*** 10. Main Entry Point ***

Create `main.go`:

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "go-fiber-rbac/config"
    "go-fiber-rbac/database"
    "go-fiber-rbac/database/migration"
    "go-fiber-rbac/routes"
)

func main() {
    config.LoadConfig()
    database.Connect()
    migration.RunMigrations()

    app := fiber.New()
    routes.Setup(app)

    app.Listen(":3000")
}
```

