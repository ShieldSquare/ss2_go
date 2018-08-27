package ss2_go

import (
	"strconv"
)

/**
 *Holds all the paresed config other than string
 */

type ApiConfigParsedData struct {
	SkipURLEnabled       bool
	RequestFilterEnabled bool
	LogsEnabled          bool
	CallType             int
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
	isLogsEnabled, err := strconv.ParseBool(apiConfig.Data.LogsEnabled)
	isRequestFilter, err := strconv.ParseBool(apiConfig.Data.RequestFilterEnabled)
	apiConfigParsedData.RequestFilterEnabled = isRequestFilter
	apiConfigParsedData.LogsEnabled = isLogsEnabled

}
