package ss2_go

import (
	"strconv"
)

/**
 *Holds all the parsed config other than string
 */

type ApiConfigParsedData struct {
	SkipURLEnabled       bool
	RequestFilterEnabled bool
	LogsEnabled          bool
	CallType             int
	SeverLogsEnabled     bool
	HTTPOnly             bool
	Secure               bool
}

var apiConfigParsedData = ApiConfigParsedData{}

func UpdateApiConfigParsedData() {
	isSkipUrl, err := strconv.ParseBool(apiConfig.Data.SkipURL)
	if err == nil {
		apiConfigParsedData.SkipURLEnabled = isSkipUrl
	}

	callType, err := strconv.Atoi(apiConfig.Data.CallType)
	if err == nil {
		apiConfigParsedData.CallType = int(callType)
	}

	isServerLogsEnabled, err := strconv.ParseBool(apiConfig.Data.ServerLogsEnabled)
	if err == nil {
		apiConfigParsedData.SeverLogsEnabled = isServerLogsEnabled
	}

	isLogsEnabled, err := strconv.ParseBool(apiConfig.Data.LogsEnabled)
	if err == nil {
		apiConfigParsedData.LogsEnabled = isLogsEnabled
	}

	isRequestFilter, err := strconv.ParseBool(apiConfig.Data.RequestFilterEnabled)
	if err == nil {
		apiConfigParsedData.RequestFilterEnabled = isRequestFilter
	}

	isSecure, err := strconv.ParseBool(apiConfig.Data.Secure)
	if err == nil {
		apiConfigParsedData.Secure = isSecure
	} else {
		apiConfigParsedData.Secure = false
	}

}
