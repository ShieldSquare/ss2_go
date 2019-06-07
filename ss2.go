package ss2_go

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/satori/go.uuid"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

/**
PayLoad generated for shieldsquare server to analysis
*/
type SSJsonObj struct {
	Zpsbd0   bool              `json:"_zpsbd0"`             //active /monitor
	Zpsbd1   string            `json:"_zpsbd1"`             //sid
	Zpsbd2   string            `json:"_zpsbd2"`             //pid
	Zpsbd3   string            `json:"_zpsbd3"`             //refer header
	Zpsbd4   string            `json:"_zpsbd4,omitempty"`   //absolute url
	Zpsbd5   string            `json:"_zpsbd5"`             //http cookie session cookie
	Zpsbd6   string            `json:"_zpsbd6"`             //ip address
	Zpsbd7   string            `json:"_zpsbd7"`             //user agent
	Zpsbd8   int               `json:"_zpsbd8,omitempty"`   //call type
	Zpsbd9   string            `json:"_zpsbd9,omitempty"`   //user id
	Zpsbda   int64             `json:"_zpsbda"`             //unix timestamp
	Zpsbdxrw string            `json:"_zpsbdxrw,omitempty"` // X-requested-with
	Zpsbdm   string            `json:"_zpsbdm,omitempy"`    //HTTP Method
	Uzma     string            `json:"__uzma"`              //cookie
	Uzmb     string            `json:"__uzmb"`              //unix timestamp
	Uzmc     string            `json:"__uzmc"`              //num of pages
	Uzmd     string            `json:"__uzmd"`              //unix timestamp
	Uzme     string            `json:"__uzme, omitempty"`
	Idn      string            `json:"idn"`                //Deployment number
	Zpsbdx   map[string]string `json:"_zpsbdx, omitempty"` //Other Headers
	Zpsbdp   int64             `json:"_zpsbdp"`            // Remote Port
	Zpsbdt   string            `json:"_zpsbdt"`            //Connector Type
	I0       string            `json:"i0,omitempty"`       //Remote Addr
	I1       string            `json:"i1,omitempty"`       //X-Forwarded-For
	I2       string            `json:"i2,omitempty"`       //HTTP_CLIENT_IP
	I3       string            `json:"i3,omitempty"`       //HTTP_X_FORWARDED-For
	I4       string            `json:"i4,omitempty"`       //x-real-ip
	I5       string            `json:"i5,omitempty"`       //HTTP_X_FORWARDED
	I6       string            `json:"i6,omitempty"`       //Proxy-Client-IP
	I7       string            `json:"i7,omitempty"`       //WL-Proxy-Client-IP
	I8       string            `json:"i8,omitempty"`       //True-Client-IP
	I9       string            `json:"i9,omitempty"`       //HTTP_X_CLUSTER_CLIENT_IP
	I10      string            `json:"i10,omitempty"`      //HTTP_FORWARDED_FOR
	I11      string            `json:"i11,omitempty"`      //HTTP-Forwarded
	I12      string            `json:"i12,omitempty"`      //HTTP_VIA
	I13      string            `json:"i13,omitempty"`      //X-True-Client-IP
	IsplitIP string            `json:"iSplitIP,omitempty"` //Split IP
	Ixff     string            `json:"ixff,omitempty"`     //ixff
}

type APIServer struct {
	Key              string      `json:"key"`
	ConnectorID      string      `json:"connector_id"`
	APIServerDomain  string      `json:"api_server_domain"`
	APIServerTimeout string      `json:"api_server_timeout"`
	APIServerSSL     string      `json:"api_server_ssl_enabled"`
	DeploymentNumber string      `json:"deployment_number"`
	Domain           interface{} `json:"domain"`
	LogPath          string      `json:"file_write_location"`
	DebugLog         string      `json:"debug_log,omitempty"`
}

type APIVersion struct {
	Status string `json:"status"`
	Data   struct {
		Version string `json:"_version"`
	}
}

type APIConfig struct {
	Status string `json:"status"`
	Data   struct {
		CallType  string `json:"_calltype"`
		Mode      string `json:"_mode"`
		Sid       string `json:"_sid"`
		SS2Domain string `json:"_ss2_domain"`
		//SS2SslEnabled        string `json:"_api_server_ssl_enabled"`
		SS2Timeout           string `json:"_timeout_value"`
		Sessid               string `json:"_sessid"`
		APIServerDomain      string `json:"_api_server_domain"`
		APIServerTimeout     string `json:"_api_server_timeout"`
		APIServerSSL         string `json:"_api_server_ssl_enabled"`
		SSBlockEnabled       string `json:"_ss_block_enabled"`
		SSCaptchaEnabled     string `json:"_ss_captcha_enabled"`
		AsyncPost            string `json:"_async_http_post"`
		SupportEmail         string `json:"_support_email"`
		LogsEnabled          string `json:"_log_enabled"`
		LogLevel             string `json:"_loglevel"`
		ServerLogsEnabled    string `json:"_server_log_enabled"`
		OtherHeaders         string `json:"_other_headers"`
		IPAddress            string `json:"_ipaddress"`
		IPIndex              string `json:"_ip_index"`
		EndPointSSL          string `json:"_enable_ssl"`
		Version              string `json:"_version"`
		RedirectDomain       string `json:"_redirect_domain"`
		DefRedirectDomain    string `json:"_d_redirect_domain"`
		SkipURL              string `json:"_skip_url"`
		SkipURLLIST          string `json:"_skip_url_list"`
		RequestFilterEnabled string `json:"_content_filter"`
		RequestFilterType    string `json:"_content_list"`
		PostURL              string `json:"_posturl"`
		TrkEvent             string `json:"_trkevent"`
		BlacklistHeaders     string `json:"_blacklist_headers"`
		WhitelistHeaders     string `json:"_whitelist_headers"`
		Secure               string `json:"_is_secure"`
		Server               string `json:"_server"`
		Port                 string `json:"_port"`
		LogPath              string `json:"_file_write_location"`
	}
}

var siemJson map[string]interface{}

var apiServer = APIServer{}
var apiVersion = APIVersion{}
var apiConfig = APIConfig{}
var ssJsonObj = SSJsonObj{}
var lastCfgTime int64
var lastVersion uint64

const MAXFILESIZE = 5242880
const MAXFILES = 5

var f, _ = os.OpenFile("/tmp/"+"ShieldSquare_GoLang.log",
	os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)

var logInfo = log.New(f, "INFO", log.LstdFlags)
var logDebug = log.New(f, "DEBUG", log.LstdFlags)
var logWarn = log.New(f, "WARN", log.LstdFlags)
var logError = log.New(f, "ERROR", log.LstdFlags)

var conn, _ = net.ListenPacket("udp", ":0")

var xRespTime = ""

var (
	httpClient *http.Client
)

var errorDesc = ""

func init() {

	configLoc := os.Getenv("PATH_TO_SS")

	file, er := os.Open(configLoc + "ss2_config.json")

	if er != nil {
		fmt.Println(er)
	}
	decoder := json.NewDecoder(file)
	err := decoder.Decode(&apiServer)
	if err != nil {
		fmt.Println("error:", err)
	}

	timeout, _ := strconv.Atoi(apiServer.APIServerTimeout)
	ssl, _ := strconv.ParseBool(apiServer.APIServerSSL)
	httpClient = createHTTPClient(timeout, ssl)
}

func checkLogFile(config APIConfig) (*os.File, interface{}) {
	var logDir = ""
	if config.Data.LogPath != "" {
		logDir = config.Data.LogPath
	} else {
		logDir = "/tmp/"
	}

	var logFile = logDir + "ShieldSquare_GoLang.log"
	fi, _ := os.Stat(logFile)
	if file_is_exists(logFile) && fi.Size() > MAXFILESIZE {
		if file_is_exists(logFile + "." + strconv.Itoa(MAXFILES)) {
			err := os.Remove(logFile + "." + strconv.Itoa(MAXFILES))
			if err != nil {
				logError.Println("Something went wrong while deleting the file : " + logFile + "." + strconv.Itoa(MAXFILES))
			}
		}

		for i := MAXFILES; i > 0; i-- {
			if file_is_exists(logFile + "." + strconv.Itoa(i)) {
				next := i + 1
				os.Rename(logFile+"."+strconv.Itoa(i), logFile+"."+strconv.Itoa(next))
			}
		}
		os.Rename(logFile, logFile+".1")
		return os.OpenFile(logFile+".1", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	}

	return os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
}

func file_is_exists(f string) bool {
	_, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func createHTTPClient(timeout int, ssl bool) *http.Client {

	transport := &http.Transport{}
	if ssl {
		certLoc := os.Getenv("PATH_TO_SS")
		certLoc = certLoc + "ShieldsquareCABundle.pem"
		Cert, err := ioutil.ReadFile(certLoc)
		if err != nil {
			fmt.Println("Error in reading cert")
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(Cert)

		tlsConf := &tls.Config{
			RootCAs:    certPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}

		transport = &http.Transport{
			TLSClientConfig: tlsConf,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Millisecond,
	}

	return client
}

type SsServiceResp struct {
	Ssresp    string `json:"ssresp"`
	DynamicJs string `json:"dynamic_js"`
	BotCode   string `json:"bot_code,omitempty"`
}

const ALLOW int = 0
const CAPTCHA int = 2
const BLOCK int = 3
const ALLOWEXP int = -1
const MOBILE int = 6

type IpRange struct {
	min net.IP
	max net.IP
}

var PrivateRanges = []IpRange{
	{
		min: net.ParseIP("10.0.0.0"),
		max: net.ParseIP("10.255.255.255"),
	},
	{
		min: net.ParseIP("172.16.0.0"),
		max: net.ParseIP("172.31.255.255"),
	},
	{
		min: net.ParseIP("192.0.0.0"),
		max: net.ParseIP("192.0.0.255"),
	},
	{
		min: net.ParseIP("192.168.0.0"),
		max: net.ParseIP("192.168.255.255"),
	},
	{
		min: net.ParseIP("198.18.0.0"),
		max: net.ParseIP("198.19.255.255"),
	},
	{
		min: net.ParseIP("127.0.0.0"),
		max: net.ParseIP("127.255.255.255"),
	},
	{
		min: net.ParseIP("100.64.0.0"),
		max: net.ParseIP("100.127.255.255"),
	},
	{
		min: net.ParseIP("0.0.0.0"),
		max: net.ParseIP("0.255.255.255"),
	},
}

func IsPrivateSubnet(IpAddress net.IP) bool {
	if ipCheck := IpAddress.To4(); ipCheck != nil {
		for _, Range := range PrivateRanges {
			if bytes.Compare(IpAddress, Range.min) >= 0 && bytes.Compare(IpAddress, Range.max) <= 0 {
				return true
			}
		}
	}
	return false
}

func SplitIP(IPList string, Index int) string {

	Ips := strings.Split(IPList, ",")
	for i := 0; i < len(Ips); i++ {
		Ips[i] = strings.Split(Ips[i], ":")[0]
	}

	Count := len(Ips)
	if Count == 1 {

		return strings.Trim(IPList, ":")
	}
	if Index > 0 && Index <= Count {
		if IsPrivateSubnet(net.ParseIP(Ips[Index-1])) == false {
			return Ips[Index-1]
		}
	}
	if Index == 0 {
		if IsPrivateSubnet(net.ParseIP(Ips[Index])) == false {
			return Ips[Index]
		}
	}
	if Index > 0 {
		rightIP := ""
		for i := Index; i < Count; i++ {
			if IsPrivateSubnet(net.ParseIP(Ips[i])) == false {
				rightIP = Ips[i]
				break
			}
		}
		return rightIP
	} else if Index < 0 {
		for j := Count + Index; j >= 0; j-- {
			if IsPrivateSubnet(net.ParseIP(Ips[j])) == false {
				return Ips[j]
			}
		}
	}
	return IPList
}

func ssApiPoll(attr string) (string, bool) {

	ssl, _ := strconv.ParseBool(apiServer.APIServerSSL)
	schema := "http://"
	if ssl {
		schema = "https://"
	}
	APIServerUrl := schema + apiServer.APIServerDomain + "/environments/" + apiServer.DeploymentNumber + attr
	request, err := http.NewRequest(http.MethodGet, APIServerUrl, nil)
	request.Header.Add("Authorization", "Bearer "+apiServer.Key)

	response, err := httpClient.Do(request)
	if err != nil {
		// panic(err)
		fmt.Println(err)
		return "", false
	}
	defer response.Body.Close()
	resp, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == http.StatusOK {
		return string(resp), true
	} else {
		return "", false
	}
}

func ValidateRequest(req *http.Request, w http.ResponseWriter, user string) ([]byte, error) {

	var sendTime int64
	var recTime int64
	var respTime int64
	var debugTime int64
	debugTime, err := strconv.ParseInt(apiServer.DebugLog, 10, 64)
	ssResp := SsServiceResp{}
	ssResp = SsServiceResp{strconv.Itoa(ALLOWEXP), "var __uzdbm_c = 2+2", ""}

	if time.Now().Unix()-lastCfgTime > 300 || (err == nil && time.Now().Unix()-lastCfgTime > debugTime) {
		response, status := ssApiPoll("/version")
		if status {
			err := json.Unmarshal([]byte(response), &apiVersion)
			fmt.Println(err)
		} else {
			return json.Marshal(ssResp)
		}
		currVersion, _ := strconv.ParseUint(apiVersion.Data.Version, 10, 64)
		if currVersion > lastVersion {
			lastVersion = currVersion
			response, status = ssApiPoll("/configuration")
			if status {
				json.Unmarshal([]byte(response), &apiConfig)
				//write update for the config
				UpdateApiConfigParsedData()

				if apiConfigParsedData.LogsEnabled == true {
					logDebug.Println("Config Received from ShieldSquare : ", response)
				}

				f, _ = checkLogFile(apiConfig)

				logInfo = log.New(f, "INFO ", log.LstdFlags|log.Lshortfile)
				logDebug = log.New(f, "DEBUG ", log.LstdFlags|log.Lshortfile)
				logWarn = log.New(f, "WARN ", log.LstdFlags|log.Lshortfile)
				logError = log.New(f, "ERROR ", log.LstdFlags|log.Lshortfile)
				//updating configuration file.

				if apiConfig.Data.APIServerDomain != apiServer.APIServerDomain || apiConfig.Data.APIServerTimeout != apiServer.APIServerTimeout || apiConfig.Data.APIServerSSL != apiServer.APIServerSSL || apiConfig.Data.LogPath != apiServer.LogPath {
					apiServer.APIServerDomain = apiConfig.Data.APIServerDomain
					apiServer.APIServerTimeout = apiConfig.Data.APIServerTimeout
					apiServer.APIServerSSL = apiConfig.Data.APIServerSSL
					apiServer.LogPath = apiConfig.Data.LogPath
					filename := os.Getenv("PATH_TO_SS") + "ss2_config.json"
					updatedJson, _ := json.Marshal(apiServer)
					ioutil.WriteFile(filename, updatedJson, 0644)
				}
			} else {
				return json.Marshal(ssResp)
			}
		}
		lastCfgTime = time.Now().Unix()
	}
	callType, _ := strconv.Atoi(apiConfig.Data.CallType)
	//initialization of variables
	TimeNowSecs := time.Now().Unix()
	Expiration := time.Now().Add(182 * 24 * time.Hour) //6 months

	// Request Filter Check
	if filter := IsFilterRequest(req.RequestURI); filter {
		ssResp = SsServiceResp{strconv.Itoa(ALLOW), "var __uzdbm_c = 2+2", ""}
		return json.Marshal(ssResp)
	}

	// Skip Url Check
	if skipurl := IsSkipUrl(getScheme(req.TLS != nil) + req.Host + req.RequestURI); skipurl {
		ssResp = SsServiceResp{strconv.Itoa(ALLOW), "var __uzdbm_c = 2+2", ""}
		return json.Marshal(ssResp)
	}

	//Multi-site check
	domainSID := strings.ToLower(apiConfig.Data.Sid)
	isMatch, sidType := CheckGetmultisite(getScheme(req.TLS != nil) + req.Host + req.RequestURI)
	if isMatch {
		domainSID = sidType[0]
		callType, _ = strconv.Atoi(sidType[1])
	}

	ssl, _ := strconv.ParseBool(apiConfig.Data.APIServerSSL)
	schema := "http://"
	if ssl {
		schema = "https://"
	}

	ssServiceUrl := schema + apiConfig.Data.APIServerDomain + "/getRequestData"
	if apiConfigParsedData.LogsEnabled == true {
		logDebug.Println("ShieldSquare Service URL : ", ssServiceUrl)
	}
	ip, Port, _ := net.SplitHostPort(req.RemoteAddr)
	userIP := ""
	splitIP := ""

	if strings.Contains(apiConfig.Data.IPAddress, "Auto") {
		userIP = strings.Trim(net.IP.String(net.ParseIP(ip)), ":")
		splitIP = userIP
	} else {
		IPIndex, _ := strconv.Atoi(apiConfig.Data.IPIndex)
		userIP = req.Header.Get(apiConfig.Data.IPAddress)
		if userIP != "" {
			userIP = strings.Replace(userIP, " ", "", -1)
			splitIP = SplitIP(userIP, IPIndex)
		} else {
			userIP = strings.Trim(net.IP.String(net.ParseIP(ip)), ":")
			if splitIP == "" {
				splitIP = userIP
			}
		}
	}

	cookieA, errA := req.Cookie("__uzma")
	cookieB, errB := req.Cookie("__uzmb")
	cookieC, errC := req.Cookie("__uzmc")
	cookieD, errD := req.Cookie("__uzmd")

	if callType == MOBILE {
		cookieE, errE := req.Cookie("__uzme")
		//if cookie not present
		if errE != nil {
			//create new cookie
			UUID, _ := uuid.NewV4()
			ssJsonObj.Uzme = UUID.String()
			E := http.Cookie{Name: "__uzme", Value: ssJsonObj.Uzme, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: true}
			http.SetCookie(w, &E)
		} else {
			ssJsonObj.Uzme = cookieE.Value
		}
	}

	var IsDigit = regexp.MustCompile(`^[0-9]+$`).MatchString

	cookieAbsent := false
	cookieTampered := false
	uzmcVal := ""
	uzmcCounter := 0

	if errA != nil || errB != nil || errC != nil || errD != nil {
		cookieAbsent = true
		uzmcVal = GenerateUzmc(0)
		if apiConfigParsedData.LogsEnabled == true {
			logError.Println("error while getting cookie")
		}
	} else {
		if len(cookieB.Value) != 10 || IsDigit(cookieB.Value) == false || len(cookieC.Value) < 12 || IsDigit(cookieC.Value) == false || len(cookieD.Value) != 10 || IsDigit(cookieD.Value) == false || len(cookieA.Value) != 36 {
			cookieTampered = true
			uzmcVal = GenerateUzmc(0)
		} else {
			uzmcSequence, _ := strconv.Atoi(cookieC.Value[5 : len(cookieC.Value)-5])
			uzmcCounter = (uzmcSequence - 7) / 3
			uzmcVal = GenerateUzmc(uzmcCounter)
		}
	}

	if cookieAbsent || cookieTampered {
		uuidVar, err := uuid.NewV4()
		if err != nil {
			if apiConfigParsedData.LogsEnabled == true {
				logError.Println("uuidVar generation failed")
			}
		}

		ssJsonObj.Uzma = uuidVar.String()
		ssJsonObj.Uzmb = strconv.FormatInt(TimeNowSecs, 10)

		A := http.Cookie{Name: "__uzma", Value: ssJsonObj.Uzma, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: true}
		B := http.Cookie{Name: "__uzmb", Value: ssJsonObj.Uzmb, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: true}

		http.SetCookie(w, &A)
		http.SetCookie(w, &B)
	} else {
		ssJsonObj.Uzma = cookieA.Value
		ssJsonObj.Uzmb = cookieB.Value
	}
	ssJsonObj.Uzmc = uzmcVal
	ssJsonObj.Uzmd = strconv.FormatInt(TimeNowSecs, 10)

	C := http.Cookie{Name: "__uzmc", Value: ssJsonObj.Uzmc, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: true}
	D := http.Cookie{Name: "__uzmd", Value: ssJsonObj.Uzmd, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: true}

	http.SetCookie(w, &C)
	http.SetCookie(w, &D)

	//for session id
	Sessid := ""
	if len(apiConfig.Data.Sessid) > 0 {
		cookieSes, err1 := req.Cookie(apiConfig.Data.Sessid)

		if err1 != nil {
			Sessid = ""
		} else {
			Sessid = cookieSes.Value
		}
	}

	ssJsonObj.Zpsbd0 = strings.Contains(apiConfig.Data.Mode, "Active")
	ssJsonObj.Zpsbd1 = strings.ToLower(domainSID)
	ssJsonObj.Zpsbd2 = GeneratePid(domainSID)
	ssJsonObj.Zpsbd3 = req.Referer()
	ssJsonObj.Zpsbd4 = getScheme(req.TLS != nil) + req.Host + req.RequestURI //rethink
	ssJsonObj.Zpsbd5 = Sessid
	ssJsonObj.Zpsbd6 = splitIP
	ssJsonObj.Zpsbd7 = req.UserAgent()
	ssJsonObj.Zpsbd8 = callType
	ssJsonObj.Zpsbd9 = user
	ssJsonObj.Zpsbda = TimeNowSecs

	ssJsonObj.Zpsbdxrw = req.Header.Get("X-Requested-With")
	ssJsonObj.Zpsbdm = req.Method

	ssJsonObj.Idn = "1234"
	if len(apiServer.DeploymentNumber) > 0 {
		ssJsonObj.Idn = apiServer.DeploymentNumber
	}

	othHeaders := make(map[string]string)
	blacklistHeaders := strings.Split(apiConfig.Data.BlacklistHeaders, ",")
	whitelistHeaders := strings.Split(apiConfig.Data.WhitelistHeaders, ",")
	if whitelistHeaders[0] == "" && blacklistHeaders[0] == "" {
		for name, headers := range req.Header {
			for _, h := range headers {
				othHeaders[name] = h
			}
		}
	}

	if blacklistHeaders[0] != "" {
		for name, headers := range req.Header {
			for _, h := range headers {
				othHeaders[name] = h
			}
		}

		for _, blacklistHeaders := range blacklistHeaders {
			delete(othHeaders, blacklistHeaders)
		}
	} else if whitelistHeaders[0] != "" {
		for name, headers := range req.Header {
			for _, h := range headers {
				for i := 0; i < len(whitelistHeaders); i++ {
					if whitelistHeaders[i] == name {
						othHeaders[name] = h
					}
				}
			}
		}
	}

	if strings.Contains(apiConfig.Data.OtherHeaders, "True") {
		ssJsonObj.Zpsbdx = othHeaders
	}

	port, err := strconv.ParseInt(Port, 10, 64)
	if err != nil {
		port = 70000
	}
	ssJsonObj.Zpsbdp = port

	ssJsonObj.Zpsbdt = apiServer.ConnectorID + " 5.3.0"

	// IP headers

	RemoteAddr, _, _ := net.SplitHostPort(req.RemoteAddr)
	ssJsonObj.I0 = net.IP.String(net.ParseIP(RemoteAddr))
	ssJsonObj.I1 = strings.Replace(req.Header.Get("X-Forwarded-For"), " ", "", -1)
	ssJsonObj.I2 = strings.Trim(req.Header.Get("HTTP_CLIENT_IP"), ":")
	ssJsonObj.I3 = req.Header.Get("HTTP_X_FORWARDED_FOR")
	ssJsonObj.I4 = req.Header.Get("x-real-ip")
	ssJsonObj.I5 = req.Header.Get("HTTP_X_FORWARDED")
	ssJsonObj.I6 = req.Header.Get("Proxy-Client-IP")
	ssJsonObj.I7 = req.Header.Get("WL-Proxy-Client-IP")
	ssJsonObj.I8 = req.Header.Get("True-Client-IP")
	ssJsonObj.I9 = req.Header.Get("HTTP_X_CLUSTER_CLIENT_IP")
	ssJsonObj.I10 = req.Header.Get("HTTP_FORWARDED_FOR")
	ssJsonObj.I11 = req.Header.Get("HTTP-Forwaded")
	ssJsonObj.I12 = req.Header.Get("HTTP_VIA")
	ssJsonObj.I13 = req.Header.Get("X-True-Client-IP")
	ssJsonObj.Ixff = SplitIP(ssJsonObj.I1, 1)

	jsonObject, _ := json.Marshal(ssJsonObj)
	if apiConfigParsedData.LogsEnabled == true {
		logDebug.Println("Body : ", string(jsonObject))
	}
	fmt.Println(string(jsonObject))

	if apiConfig.Data.Mode == "Monitor" && apiConfig.Data.AsyncPost == "True" {
		AsyncSendreq2ss(ssServiceUrl, jsonObject)
		ssResp = SsServiceResp{strconv.Itoa(ALLOW), "var __uzdbm_c = 2+2", ""}
	} else {
		sendTime = time.Now().UnixNano() / int64(time.Millisecond)
		ssResponse := SyncSendreq2ss(ssServiceUrl, jsonObject)
		recTime = time.Now().UnixNano() / int64(time.Millisecond)
		respTime = recTime - sendTime

		if ssResponse != "" {
			json.Unmarshal([]byte(ssResponse), &ssResp)
			ssResp = SsServiceResp{ssResp.Ssresp, ssResp.DynamicJs, ssResp.BotCode}
			Resp, err := strconv.Atoi(ssResp.Ssresp)
			if Resp >= CAPTCHA && Resp <= BLOCK && err == nil && callType != MOBILE {
				Query := getRedirectQueryParams(ssJsonObj, apiConfig.Data.SupportEmail, apiConfig.Data.RedirectDomain)
				Type := ""
				schema := "http://"
				if strings.Contains(apiConfig.Data.EndPointSSL, "True") {
					schema = "https://"
				}
				if ssResp.Ssresp == strconv.Itoa(CAPTCHA) && strings.Contains(apiConfig.Data.SSCaptchaEnabled, "True") {
					Type = "/captcha?"
					RedirUrl := schema + apiConfig.Data.RedirectDomain + Type + Query
					http.Redirect(w, req, RedirUrl, http.StatusTemporaryRedirect)
				}
				if ssResp.Ssresp == strconv.Itoa(BLOCK) && strings.Contains(apiConfig.Data.SSBlockEnabled, "True") {
					Type = "/block?"
					RedirUrl := schema + apiConfig.Data.RedirectDomain + Type + Query
					http.Redirect(w, req, RedirUrl, http.StatusTemporaryRedirect)
				}
			}
			logDebug.Println("ShieldSquare Response : " + ssResponse)
		}

	}

	if apiConfigParsedData.SeverLogsEnabled && apiConfig.Data.Mode == "Active" {
		siemJson = make(map[string]interface{})
		siemJson["IP"] = ssJsonObj.Zpsbd6
		siemJson["UA"] = ssJsonObj.Zpsbd7
		siemJson["URL"] = ssJsonObj.Zpsbd4
		siemJson["Referrer"] = ssJsonObj.Zpsbd3
		siemJson["Session"] = ssJsonObj.Zpsbd5
		siemJson["Username"] = ssJsonObj.Zpsbd9
		if errorDesc != "" {
			siemJson["Error"] = errorDesc
		} else {
			siemJson["Response Time"] = strconv.Itoa(int(respTime)) + "ms"
			siemJson["Response"] = ssResp
			siemJson["X-Response-Time"] = xRespTime
		}

		logSIEM(siemJson, apiConfig)
	}

	if callType == MOBILE {
		if (apiConfig.Data.SSCaptchaEnabled == "True" && ssResp.Ssresp == "2") || (apiConfig.Data.SSBlockEnabled == "True" && ssResp.Ssresp == "3") {
			w.Header().Add("_uzmcr", GetUzmcr(ssResp.Ssresp))
		}
		if apiConfig.Data.PostURL != "" {
			w.Header().Add("posturl", apiConfig.Data.PostURL)
		}
		if apiConfig.Data.TrkEvent != "" {
			w.Header().Add("trkevent", apiConfig.Data.TrkEvent)
		}
	}
	f.Sync()
	return json.Marshal(ssResp)

}

func SyncSendreq2ss(ssServiceUrl string, jsonObject []byte) string {

	req, _ := http.NewRequest(http.MethodPost, ssServiceUrl, bytes.NewBuffer(jsonObject))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		xRespTime = resp.Header.Get("x-response-time")
		fmt.Println(string(body))
		if err != nil {
			errorDesc = string(err.Error())
		}
		return string(body)
	} else {
		if err != nil {
			errorDesc = string(err.Error())
		}
		return ""
	}
}

func AsyncSendreq2ss(ssServiceUrl string, jsonObject []byte) {

	req, _ := http.NewRequest(http.MethodPost, ssServiceUrl, bytes.NewBuffer(jsonObject))
	req.Header.Set("Content-Type", "application/json")

	go func() {
		resp, err := httpClient.Do(req)
		if err != nil {
			if apiConfigParsedData.LogsEnabled == true {
				errorDesc = string(err.Error())
				logError.Println("sync_post error ", err)
			}
		}
		if resp != nil {
			defer resp.Body.Close()
		}
	}()
}

func GenerateUzmc(uzmcCounter int) string {
	count := ((uzmcCounter + 1) * 3) + 7
	uzmc := strconv.Itoa(randomNum(10000, 99999)) + strconv.Itoa(count) + strconv.Itoa(randomNum(10000, 99999))
	return uzmc
}

func GeneratePid(sid string) string {
	b := strings.Split(sid, "-")
	s := strings.ToLower(strconv.FormatInt(int64(time.Now().Unix()), 16))
	return randomHex(10000, 65000) + randomHex(10000, 65000) + "-" + b[3] + "-" + reverseStr(s[len(s)-4:]) + "-" + randomHex(10000, 65000) + "-" + randomHex(10000, 65000) + randomHex(10000, 65000) + randomHex(10000, 65000)
}

func randomHex(min, max int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	return strings.ToLower(strconv.FormatInt(int64(rand.Intn(max-min)+min), 16))
}

func randomNum(min, max int) int {
	rand.Seed(time.Now().UTC().UnixNano())
	return rand.Intn(max-min) + min
}

func reverseStr(str string) string {
	if str != "" {
		return reverseStr(str[1:]) + str[:1]
	} else {
		return ""
	}
}

func getScheme(scheme bool) string {
	if scheme {
		return "https://"
	} else {
		return "http://"
	}
}

func RandomString(strlen int, charset string) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	result := make([]byte, strlen)
	for i := range result {
		result[i] = charset[r.Intn(len(charset))]
	}
	return string(result)
}

func GenerateUUID() string {
	UUID, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return UUID.String()
}

func getRedirectQueryParams(ssJsonObj SSJsonObj, EmailID string, RedirDomain string) string {

	if !strings.Contains(RedirDomain, strings.Trim(apiConfig.Data.DefRedirectDomain, "")) {
		cssa := url.QueryEscape(ssJsonObj.Zpsbd4)
		InputDigest := ssJsonObj.Zpsbd1 + ssJsonObj.Zpsbd4
		Digest := sha1.Sum([]byte(InputDigest))
		cssb := hex.EncodeToString(Digest[:])
		cssc := base64.StdEncoding.EncodeToString([]byte(StringReverse(ssJsonObj.Zpsbd1)))
		return "ssa=" + cssa + "&ssb=" + cssb + "&ssc=" + cssc
	}

	if EmailID == "" {
		EmailID = "contactus@shieldsquare.com"
	}
	Digits := "0123456789"
	CharDigits0 := "0123456789abcdef"
	UzmcSequence := ssJsonObj.Uzmc[5 : len(ssJsonObj.Uzmc)-5]
	UzmaFirstPart := ""
	UzmaSeconPart := ""
	IPtoProcess := ssJsonObj.Zpsbd6
	if len(ssJsonObj.Uzma) <= 20 {
		UzmaFirstPart = ssJsonObj.Uzma
		UzmaSeconPart = ""
	} else {
		UzmaFirstPart = ssJsonObj.Uzma[0:20]
		UzmaSeconPart = ssJsonObj.Uzma[20:len(ssJsonObj.Uzma)]
	}
	ssa := GenerateUUID()
	ssc := url.QueryEscape(ssJsonObj.Zpsbd4)
	ssi := ssJsonObj.Zpsbd2
	ssk := EmailID
	ssm := RandomString(17, Digits) + UzmcSequence + RandomString(13, Digits)

	DecodeUrl, _ := url.QueryUnescape(ssJsonObj.Zpsbd4)
	InputDigest := ssJsonObj.Zpsbd1 + ssJsonObj.Zpsbd5 + DecodeUrl + UzmcSequence + ssJsonObj.Zpsbd2 + ssJsonObj.Zpsbd7 + EmailID + IPtoProcess
	Digest := sha1.Sum([]byte(InputDigest))
	DigestStr := hex.EncodeToString(Digest[:])

	ssn := RandomString(8, CharDigits0) + DigestStr[0:20] + RandomString(8, CharDigits0) + UzmaFirstPart + RandomString(5, CharDigits0)
	sso := RandomString(5, CharDigits0) + UzmaSeconPart + RandomString(8, CharDigits0) + DigestStr[20:40] + RandomString(8, CharDigits0)

	ssp := RandomString(10, Digits) + ssJsonObj.Uzmb[0:5] + RandomString(5, Digits) + ssJsonObj.Uzmd[0:5] + RandomString(10, Digits)
	ssq := RandomString(7, Digits) + ssJsonObj.Uzmb[5:10] + RandomString(9, Digits) + ssJsonObj.Uzmd[5:10] + RandomString(15, Digits)

	ssr := base64.StdEncoding.EncodeToString([]byte(IPtoProcess))

	sst := ssJsonObj.Zpsbd7

	ssv := base64.StdEncoding.EncodeToString([]byte(ssJsonObj.Zpsbd9))
	ssw := ssJsonObj.Zpsbd5

	query := "ssa=" + ssa + "&ssc=" + ssc + "&ssi=" + ssi +
		"&ssk=" + ssk + "&ssm=" + ssm + "&ssn=" + ssn + "&sso=" + sso +
		"&ssp=" + ssp + "&ssq=" + ssq + "&ssr=" + ssr + "&sst=" + sst +
		"&ssv=" + ssv + "&ssw=" + ssw

	return query

}

func logSIEM(siemJson map[string]interface{}, config APIConfig) {

	siemLog, _ := json.Marshal(siemJson)
	logLevel := "debug"
	if apiConfig.Data.LogLevel != "" {
		logLevel = apiConfig.Data.LogLevel
	}

	if config.Data.Server != "" || config.Data.Port != "" {
		addr := config.Data.Server + ":" + config.Data.Port
		dest, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			logError.Println("Something went wrong while creating UDP. Printing logs into ShieldSquare Logs.")
			printSIEM(siemJson, logLevel)
		}
		conn.WriteTo([]byte(siemLog), dest)
	} else {
		logError.Println("Printing SIEM logs into ShieldSquare log because Server or Port is empty.")
		printSIEM(siemJson, logLevel)
	}

}

func printSIEM(siemJson map[string]interface{}, logLevel string) {
	siemLog, err := json.Marshal(siemJson)
	if err != nil {
		logError.Println("Error while creating SIEM Log")
	}
	if strings.ToLower(logLevel) == "info" {
		logInfo.Println("SIEM Log :", string(siemLog))
	} else if strings.ToLower(logLevel) == "debug" {
		logDebug.Println("SIEM Log :", string(siemLog))
	} else if strings.ToLower(logLevel) == "warn" {
		logWarn.Println("SIEM Log :", string(siemLog))
	} else if strings.ToLower(logLevel) == "err" {
		logError.Println("SIEM Log :", string(siemLog))
	}

}
