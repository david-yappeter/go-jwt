package logger

import (
	logger "gorm.io/gorm/logger"
	"log"
	"os"
	"time"
)

//Generated By github.com/davidyap2002/GormCrudGenerator

//InitLog Database Connection Log Config
func InitLog() logger.Interface {
	newLogger := logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
		Colorful:      true,
		LogLevel:      logger.Info,
		SlowThreshold: time.Second,
	})
	return newLogger
}