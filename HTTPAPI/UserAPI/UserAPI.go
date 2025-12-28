package UserAPI

import (
	"UserService/config"
	"UserService/dao"
	"UserService/logger"
	"UserService/models"
	"UserService/utils"
	"UserService/validator"
	"crypto/rand"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"net/http"
	"time"
)

var (
	tc *cache.Cache
)

func init() {
	tc = cache.New(time.Minute*10, time.Minute)
}

func HandleAllocEmailVerifyCode(sendMailFunc func(email, code string) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request = &struct {
			Email string `json:"email"`
		}{}
		if err := c.BindJSON(request); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 10001,
				"msg":  "bad request",
			})
			return
		}
		logger.Println(request)
		if !validator.VerifyEmailFormat(request.Email) {
			c.JSON(http.StatusOK, gin.H{
				"code": 10002,
				"msg":  "param invalid",
			})
			return
		}

		verifyCode, err := generateSecureVerificationCode()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50007,
				"msg":  "internal error",
			})
			logger.Println("generate verification code error:", err)
			return
		}

		err = sendMailFunc(request.Email, verifyCode)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50008,
				"msg":  "send email failed",
			})
			logger.Println("send mail error:", err)
			return
		}

		tc.SetDefault(request.Email, map[string]interface{}{
			"time": utils.GetUnixTime(),
			"code": verifyCode,
		})

		logger.Println("验证码已发送至邮箱:", maskEmail(request.Email))

		c.JSON(http.StatusOK, gin.H{
			"code": 0,
		})
	}
}

func HandleUserRegister(tokenFunc func(c *gin.Context, user *models.User) (expire time.Time, token string, err error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request = &struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Code     string `json:"code"`
		}{}
		if err := c.BindJSON(request); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 10001,
				"msg":  "bad request",
			})
			return
		}

		// Validate email format
		if !validator.VerifyEmailFormat(request.Email) {
			c.JSON(http.StatusOK, gin.H{
				"code": 10002,
				"msg":  "invalid email format",
			})
			return
		}

		// Validate password
		if err := validatePassword(request.Password); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 10003,
				"msg":  err.Error(),
			})
			return
		}

		if config.UseEmailVerify { // 验证 email
			if p, ok := tc.Get(request.Email); !ok {
				c.JSON(http.StatusOK, gin.H{
					"code": 20002,
					"msg":  "verify code expired",
				})
				return
			} else {
				mm, ok := p.(map[string]interface{})
				if !ok {
					logger.Println("[User] cache data type error")
					c.JSON(http.StatusOK, gin.H{
						"code": 50003,
						"msg":  "internal error",
					})
					return
				}
				code, ok := mm["code"].(string)
				if !ok || code != request.Code {
					c.JSON(http.StatusOK, gin.H{
						"code": 20003,
						"msg":  "verify code invalid",
					})
					return
				}
			}

			// 验证通过
			tc.Delete(request.Email)
		}
		// 执行注册
		user, err := models.AddUser(dao.SharedDB(), request.Email, request.Password)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50003,
				"msg":  "internal error",
			})
			logger.Println("[User] register error:", err)
			return
		}
		expire, tokenString, err := tokenFunc(c, user)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50006,
				"msg":  "internal error",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"code":   0,
			"token":  tokenString,
			"expire": expire.Unix(),
		})
	}
}

func HandleUserLogin(tokenFunc func(c *gin.Context, user *models.User) (expire time.Time, token string, err error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request = &struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}
		if err := c.BindJSON(request); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 10001,
				"msg":  "bad request",
			})
			return
		}

		// 执行登录
		user, err := models.GetUsersByEmail(dao.SharedDB(), request.Email)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50003,
				"msg":  "internal error",
			})
			logger.Println("[User] get user by email error:", err)
			return
		}
		if ok, err := utils.ComparePasswordAndHash(request.Password, user.Password); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50004,
				"msg":  "internal error",
			})
			logger.Println(err)
			return
		} else {
			if !ok {
				c.JSON(http.StatusOK, gin.H{
					"code": 50005,
					"msg":  "login fail",
				})
				return
			}
		}
		expire, tokenString, err := tokenFunc(c, user)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50006,
				"msg":  "internal error",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"code":   0,
			"token":  tokenString,
			"expire": expire.Unix(),
		})
	}
}

func HandleUserRefreshToken(tokenFunc func(c *gin.Context, user *models.User) (expire time.Time, token string, err error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.Value("uid")
		if uid == nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 40001,
				"msg":  "unauthorized",
			})
			return
		}
		uidStr, ok := uid.(string)
		if !ok {
			logger.Println("[User] uid type assertion error")
			c.JSON(http.StatusOK, gin.H{
				"code": 50003,
				"msg":  "internal error",
			})
			return
		}
		user, err := models.GetUsersByUID(dao.SharedDB(), uidStr)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50003,
				"msg":  "internal error",
			})
			logger.Println("[User] get user by uid error:", err)
			return
		}
		expire, tokenString, err := tokenFunc(c, user)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 50006,
				"msg":  "internal error",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"code":   0,
			"token":  tokenString,
			"expire": expire.Unix(),
		})
	}
}

// generateSecureVerificationCode generates a cryptographically secure 6-digit verification code
func generateSecureVerificationCode() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Convert 3 bytes to a number and map to 6-digit range (100000-999999)
	code := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return fmt.Sprintf("%06d", code%900000+100000), nil
}

// maskEmail masks email address for logging (e.g., "user@example.com" -> "u***@e***.com")
func maskEmail(email string) string {
	if len(email) < 3 {
		return "***"
	}
	parts := []rune(email)
	atIndex := -1
	for i, ch := range parts {
		if ch == '@' {
			atIndex = i
			break
		}
	}
	if atIndex <= 0 {
		return "***"
	}
	// Mask username part (keep first char)
	for i := 1; i < atIndex; i++ {
		parts[i] = '*'
	}
	// Mask domain part (keep first char after @)
	if atIndex+2 < len(parts) {
		dotIndex := -1
		for i := atIndex + 1; i < len(parts); i++ {
			if parts[i] == '.' {
				dotIndex = i
				break
			}
		}
		if dotIndex > atIndex+1 {
			for i := atIndex + 2; i < dotIndex; i++ {
				parts[i] = '*'
			}
		}
	}
	return string(parts)
}

// validatePassword validates password strength
func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 72 {
		return fmt.Errorf("password too long (max 72 characters)")
	}
	return nil
}
