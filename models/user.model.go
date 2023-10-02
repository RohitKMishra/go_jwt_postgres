package models

import (
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// This struct represents the underlying SQL table for user. It is a blue print for gormfor generating the corresponding SQL table
type User struct {
	ID        *uuid.UUID `gorm:"type:uuid;primary_key"`
	Name      string     `gorm:"type:varchar(100);not null"`
	Email     string     `gorm:"type:varchar(100);uniqueIndex;not null"`
	Password  string     `gorm:"type:varchar(100); not null"`
	Role      *string    `gorm:"type:varchar(50);default:user;not null"`
	Provider  *string    `gorm:"type:varchar(50);default:local;not null"`
	Photo     *string    `gorm:"not null;default:'default.png'"`
	Verified  *bool      `gorm:"not null;default:false"`
	CreatedAt *time.Time `gorm:"not null;default:now()"`
	UpdatedAt *time.Time `gorm:"not null;default:now()"`
}

// represents the structure for signUp request body
type SignUpInput struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name" validate:"required"`
	Email           string    `json:"email" validate:"required"`
	Password        string    `json:"password" validate:"required,min=8"`
	PasswordConfirm string    `json:"passwordConfirm" validate:"required,min=8"`
	Photo           string    `json:"photo"`
}

// represents the structure for signIn request body
type SignInInput struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type UserResponse struct {
	ID        uuid.UUID `json:"id,omitempty"`
	Name      string    `json:"name,omitempty"`
	Email     string    `json:"email,omitempty"`
	Role      string    `json:"role,omitempty"`
	Photo     string    `json:"photo,omitempty"`
	Provider  string    `json:"provider"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func FilterUserRecord(user *User) UserResponse {
	return UserResponse{
		ID:        *user.ID,
		Name:      user.Name,
		Email:     user.Email,
		Role:      *user.Role,
		Photo:     *user.Photo,
		Provider:  *user.Provider,
		CreatedAt: *user.CreatedAt,
		UpdatedAt: *user.UpdatedAt,
	}
}

var validate = validator.New()

type ErrorResponse struct {
	Field string `json:"field"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// The validateStruct function will be used to validate the request body against a specified validation schema. If the request body does not match the schema, the function will return relevant validation errors to the client.

func ValidateStruct[T any](payload T) []*ErrorResponse {
	var errors []*ErrorResponse
	err := validate.Struct(payload)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			var element ErrorResponse
			element.Field = err.StructNamespace()
			element.Tag = err.Tag()
			element.Value = err.Param()
			errors = append(errors, &element)
		}
	}
	return errors
}
