package logging

import "log"

// For now, simple wrapper around the standard log package. Can be replaced with zap/logrus.
func Info(format string, v ...interface{}) {
    log.Printf("INFO: "+format, v...)
}

func Error(format string, v ...interface{}) {
    log.Printf("ERROR: "+format, v...)
}
