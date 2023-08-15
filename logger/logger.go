package logger

import (
	"io"
	"log"
	"os"
)

type Config struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	fatalLogger *log.Logger
}

func NewWithDatetime() *Config {
	return &Config{
		debugLogger: log.New(os.Stderr, "DBG | ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix),
		infoLogger:  log.New(os.Stderr, "INF | ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix),
		warnLogger:  log.New(os.Stderr, "WRN | ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix),
		errorLogger: log.New(os.Stderr, "ERR | ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix),
		fatalLogger: log.New(os.Stderr, "FTL | ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix),
	}
}

func NewWithoutDatetime() *Config {
	return &Config{
		debugLogger: log.New(os.Stderr, "DBG | ", log.Lmsgprefix),
		infoLogger:  log.New(os.Stderr, "INF | ", log.Lmsgprefix),
		warnLogger:  log.New(os.Stderr, "WRN | ", log.Lmsgprefix),
		errorLogger: log.New(os.Stderr, "ERR | ", log.Lmsgprefix),
		fatalLogger: log.New(os.Stderr, "FTL | ", log.Lmsgprefix),
	}
}

func (c *Config) EnableVerbose() {
	c.debugLogger.SetOutput(os.Stderr)
}

func (c *Config) DisableVerbose() {
	c.debugLogger.SetOutput(io.Discard)
}

func (c *Config) Debugf(format string, v ...any) {
	c.debugLogger.Printf(format, v...)
}

func (c *Config) Infof(format string, v ...any) {
	c.infoLogger.Printf(format, v...)
}

func (c *Config) Warnf(format string, v ...any) {
	c.warnLogger.Printf(format, v...)
}

func (c *Config) Errorf(format string, v ...any) {
	c.errorLogger.Printf(format, v...)
}

func (c *Config) Fatalf(format string, v ...any) {
	c.fatalLogger.Fatalf(format, v...)
}
