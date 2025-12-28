package models

import (
	"UserService/dao/tables"
	"UserService/utils"
	"errors"
	"gorm.io/gorm"
)

// User represents a user of the system.
type User struct {
	BasicModel
	UID      string `gorm:"primarykey"`
	Username string
	Email    string `gorm:"primaryKey,index"`
	Password string
}

func init() {
	tables.Add(&User{})
}

// UserWithEmailExists returns whether a user with the given email exists.
func UserWithEmailExists(db *gorm.DB, email string) (bool, error) {
	var user User
	result := db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, result.Error
	}
	return true, nil
}

// UserWithNameExists returns whether a user with the given name exists.
func UserWithNameExists(db *gorm.DB, username string) (bool, error) {
	var user User
	result := db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, result.Error
	}
	return true, nil
}

// GetUsersByName returns the users with the given name (will always be 1, as usernames are unique).
func GetUsersByName(db *gorm.DB, username string) ([]*User, error) {
	var users []*User
	err := db.Where("username LIKE ? ", username).Find(&users).Error
	return users, err
}

func GetUsersByEmail(db *gorm.DB, email string) (*User, error) {
	var user *User
	result := db.Where("email = ? ", email).Find(&user)
	if result.RowsAffected != 1 {
		return nil, ErrNotExist
	}
	return user, nil
}

func GetUsersByUID(db *gorm.DB, uid string) (*User, error) {
	var user *User
	result := db.Where("uid = ? ", uid).Find(&user)
	if result.RowsAffected != 1 {
		return nil, ErrNotExist
	}
	return user, nil
}

// AddUser stores the user with the given data into the system's database.
func AddUser(db *gorm.DB, email string, password string) (*User, error) {
	// Check if user already exists
	exists, err := UserWithEmailExists(db, email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrExist
	}

	// Create new user
	user := &User{
		UID:      utils.GenerateId(),
		Email:    email,
		Password: utils.GenerateHashedPassword(password),
	}
	result := db.Create(user)
	if result.Error != nil {
		return nil, result.Error
	}
	return user, nil
}
