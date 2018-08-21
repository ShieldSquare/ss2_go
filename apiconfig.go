package ss2_go

import "strconv"

/**
 *Holds all the paresed config other than string
 */

type ApiConfigParsedData struct {
	SkipURLEnabled       bool
	RequestFilterEnabled bool
}

var apiConfigParsedData = ApiConfigParsedData{}

func UpdateApiConfigParsedData(){
	isSkipUrl,err:= strconv.ParseBool(apiConfig.Data.SkipURL)
	if err==nil{
		apiConfigParsedData.SkipURLEnabled=isSkipUrl
	}
	isRequestFilter,err:=strconv.ParseBool(apiConfig.Data.RequestFilterEnabled)
	apiConfigParsedData.RequestFilterEnabled = isRequestFilter
}