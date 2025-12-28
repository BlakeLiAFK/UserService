package HTTPAPI

import (
    "UserService/HTTPAPI/UserAPI"
    "UserService/HTTPAPI/auth"
    "UserService/config"
    "UserService/logger"
    "UserService/models"
    "UserService/utils"
    "UserService/utils/limit"
    "github.com/gin-gonic/gin"
    "golang.org/x/time/rate"
    "net/http"
    "time"
)

func InitGinAPI(r *gin.Engine) {
    authFunc, genTokenFunc := auth.New(config.JWTKey)

    onGenerateJWTToken := func(c *gin.Context, user *models.User) (expire time.Time, token string, err error) {
        logger.Println("生成jwt>>", c.Request.RequestURI)
        // 这里可以根据 uri, 来处理 gin.Content 里的 data 数据
        return genTokenFunc(user.UID, config.JWTExpire, map[string]interface{}{})
    }
    api := r.Group("api")
    // 限流器
    api.Use(limit.NewRateLimiter(func(c *gin.Context) string {
        return utils.GetClientIPByHeaders(c.Request)
    }, func(c *gin.Context) (*rate.Limiter, time.Duration) {
        // limit 10 qps/clientIp and permit bursts of at most 10 tokens, and the limiter expire is 1 hour
        return rate.NewLimiter(rate.Every(100*time.Millisecond), 10), time.Hour
    }, func(c *gin.Context) {
        c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
            "code": -2,
            "msg":  "too many requests",
        })
    }))

    api.POST("/user/register", UserAPI.HandleUserRegister(onGenerateJWTToken))
    api.POST("/user/login", UserAPI.HandleUserLogin(onGenerateJWTToken))
    api.GET("/user/refresh_token", authFunc, UserAPI.HandleUserRefreshToken(onGenerateJWTToken))

    if config.UseEmailVerify {
        api.POST("/user/alloc_email_verify_code", UserAPI.HandleAllocEmailVerifyCode(func(email, code string) error {
            // TODO: 执行发送邮件逻辑
            // 示例: sendEmail(email, "验证码: " + code)
            logger.Println("需要发送验证码到邮箱:", email)
            return nil
        }))
    }
}
