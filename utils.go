package ss2

import (
		"regexp"
	"strings"
	"strconv"
	"math/rand"
)

/**
 * StringReverse
 * This method takes a string and return reverse of the string
 */
func StringReverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

/**
 * Check_GetMultiSite
 * Regex Match with domain json for MultiSite Feature
 * If regex matched with url return the sid and call type associated to that regex
 */

 func Check_GetMultiSite(url string) (bool, []string){
 	var multisite []string
		if apiServer.Domain!=nil{
			domains := apiServer.Domain.(map[string]interface{})
			for key, val := range domains {
				if matched,_:= regexp.MatchString("(.*)"+key+"(.*)",url);matched {
					match:=val.([]interface{})
					multisite[0]=match[0].(string)
					multisite[1]=match[1].(string)
					return true, multisite
				}
			}
		}
		return false,nil
 }

 /**
  * IsFilterRequest
  * Regex Match With URL extension , if matched allow
  */

func IsFilterRequest(url string) bool  {
	//read all the pattern and check if match
	if apiConfigParsedData.RequestFilterEnabled {
		isFiltered,_:=regexp.MatchString(".*\\.(" + apiConfig.Data.RequestFilterType + ")",url)
		return isFiltered
	}
	return false
}

/**
 * IsSkipUrl
 * Split all the patterna and matches with url
 * if matched return true else false
 */

 func IsSkipUrl(url string) bool{
 	if apiConfigParsedData.SkipURLEnabled{
 		urlList:=strings.Split(apiConfig.Data.SkipURLLIST,",")
 		for i:= range urlList{
			isSkip,_:=regexp.MatchString(urlList[i],url)
			return isSkip
		}
	}
 	return false
 }

 /*
  * Uzmcr
  * generate a header with name uzmcr
  */

  func GetUzmcr(val string) string {
  	uzmcr:=4
  	ssresp,err:=strconv.Atoi(val)
  	if err!=nil{
		randomNumber:=rand.Intn(100 - 1) + 1
		uzmcr=(4*randomNumber)+ssresp
	}
	return string(uzmcr)
  }
