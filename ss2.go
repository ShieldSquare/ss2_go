package ss2_go

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"github.com/satori/go.uuid"
	"io/ioutil"
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
	Zpsbdp   int64             `json:"_zpsbp"`             // Remote Port
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
	LogPath          string      `json:"log_dir"`
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
		SkipURL              string `json:"_skip_url"`
		SkipURLLIST          string `json:"_skip_url_list"`
		RequestFilterEnabled string `json:"_content_filter"`
		RequestFilterType    string `json:"_content_list"`
		PostURL              string `json:"_posturl"`
		TrkEvent             string `json:"_trkevent"`
		BlacklistHeaders     string `json:"_blacklist_headers"`
		WhitelistHeaders     string `json:"_whitelist_headers"`
		HTTPOnly             string `json:"_is_httponly"`
		Secure               string `json:"_is_secure"`
	}
}

type SIEM_JSON struct {
	IP           string
	UA           string
	URL          string
	Referrer     string
	Session      string
	Username     string
	ResponseTime int64
	Error        string
}

var apiServer = APIServer{}
var apiVersion = APIVersion{}
var apiConfig = APIConfig{}
var ssJsonObj = SSJsonObj{}
var last_Cfg_time int64
var last_Version uint64

var (
	httpClient *http.Client
)

var errorDesc string

func init() {
	configLoc := os.Getenv("PATH_TO_SS")
	//configLoc = configLoc + "ss2_config.json"
	//file, er := os.Open("/root/go/ss2_config.json")
	file, er := os.Open(configLoc + "ss2_config.json")

	if er != nil {
		fmt.Println(er)
	}
	decoder := json.NewDecoder(file)
	err := decoder.Decode(&apiServer)
	if err != nil {
		fmt.Println("error:", err)
	}

	flag.Lookup("log_dir").Value.Set(apiServer.LogPath)
	flag.Lookup("v").Value.Set("2")
	flag.Parse()

	timeout, _ := strconv.Atoi(apiServer.APIServerTimeout)
	ssl, _ := strconv.ParseBool(apiServer.APIServerSSL)
	httpClient = createHTTPClient(timeout, ssl)
}

func createHTTPClient(timeout int, ssl bool) *http.Client {

	transport := &http.Transport{}
	if ssl {
		certLoc := os.Getenv("PATH_TO_SS")
		certLoc = certLoc + "ShieldsquareCABundle.pem"
		//Cert, err := ioutil.ReadFile("/root/go/ShieldsquareCABundle.pem")
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

type SS_service_resp struct {
	Ssresp     string `json:"ssresp"`
	Dynamic_js string `json:"dynamic_js"`
	BotCode    string `json:"bot_code,omitempty"`
}

const ALLOW int = 0
const MONITOR int = 1
const CAPTCHA int = 2
const BLOCK int = 3
const FFD int = 4
const ALLOW_EXP int = -1
const MOBILE int = 6

type IpRange struct {
	min net.IP
	max net.IP
}

var PrivateRanges = []IpRange{
	IpRange{
		min: net.ParseIP("10.0.0.0"),
		max: net.ParseIP("10.255.255.255"),
	},
	IpRange{
		min: net.ParseIP("172.16.0.0"),
		max: net.ParseIP("172.31.255.255"),
	},
	IpRange{
		min: net.ParseIP("192.0.0.0"),
		max: net.ParseIP("192.0.0.255"),
	},
	IpRange{
		min: net.ParseIP("192.168.0.0"),
		max: net.ParseIP("192.168.255.255"),
	},
	IpRange{
		min: net.ParseIP("198.18.0.0"),
		max: net.ParseIP("198.19.255.255"),
	},
	IpRange{
		min: net.ParseIP("127.0.0.0"),
		max: net.ParseIP("127.255.255.255"),
	},
	IpRange{
		min: net.ParseIP("100.64.0.0"),
		max: net.ParseIP("100.127.255.255"),
	},
	IpRange{
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
		for i := Index; Index < Count; i++ {
			if IsPrivateSubnet(net.ParseIP(Ips[i])) == false {
				return Ips[i]
			}
		}
	} else if Index < 0 {
		for j := Count + Index; j >= 0; j-- {
			if IsPrivateSubnet(net.ParseIP(Ips[j])) == false {
				return Ips[j]
			}
		}
	}
	return IPList
}

func ss_api_poll(attr string) (string, bool) {

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
		//return "", false
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
	var debug_time int64
	debug_time, err := strconv.ParseInt(apiServer.DebugLog, 10, 64)
	ss_Resp := SS_service_resp{}
	ss_Resp = SS_service_resp{strconv.Itoa(ALLOW_EXP), "var __uzdbm_c = 2+2", ""}

	if time.Now().Unix()-last_Cfg_time > 300 || (err == nil && time.Now().Unix()-last_Cfg_time > debug_time) {
		response, status := ss_api_poll("/version")
		if status {
			err := json.Unmarshal([]byte(response), &apiVersion)
			fmt.Println(err)
		} else {
			return json.Marshal(ss_Resp)
		}
		curr_Version, _ := strconv.ParseUint(apiVersion.Data.Version, 10, 64)
		if curr_Version > last_Version {
			last_Version = curr_Version
			response, status = ss_api_poll("/configuration")
			if status {
				json.Unmarshal([]byte(response), &apiConfig)
				//write update for the config
				UpdateApiConfigParsedData()

				//updating configuration file.
				if apiConfig.Data.APIServerDomain != apiServer.APIServerDomain || apiConfig.Data.APIServerTimeout != apiServer.APIServerTimeout || apiConfig.Data.APIServerSSL != apiServer.APIServerSSL {
					apiServer.APIServerDomain = apiConfig.Data.APIServerDomain
					apiServer.APIServerTimeout = apiConfig.Data.APIServerTimeout
					apiServer.APIServerSSL = apiConfig.Data.APIServerSSL
					filename := os.Getenv("PATH_TO_SS") + "ss2_config.json"
					updatedJson, _ := json.Marshal(apiServer)
					ioutil.WriteFile(filename, updatedJson, 0644)
				}
			} else {
				return json.Marshal(ss_Resp)
			}
		}
		last_Cfg_time = time.Now().Unix()
	}
	call_type, _ := strconv.Atoi(apiConfig.Data.CallType)
	//initialization of variables
	TimeNowSecs := time.Now().Unix()
	Expiration := time.Now().Add(182 * 24 * time.Hour) //6 months

	// Request Filter Check
	if filter := IsFilterRequest(req.RequestURI); filter {
		ss_Resp = SS_service_resp{strconv.Itoa(ALLOW), "var __uzdbm_c = 2+2", ""}
		return json.Marshal(ss_Resp)
	}

	// Skip Url Check
	if skipurl := IsSkipUrl(getScheme(req.TLS != nil) + req.Host + req.RequestURI); skipurl {
		ss_Resp = SS_service_resp{strconv.Itoa(ALLOW), "var __uzdbm_c = 2+2", ""}
		return json.Marshal(ss_Resp)
	}

	// multisite check Pradeep
	domainSID := strings.ToLower(apiConfig.Data.Sid)
	isMatch, sidType := Check_GetMultiSite(getScheme(req.TLS != nil) + req.Host + req.RequestURI)
	if isMatch {
		domainSID = sidType[0]
		call_type, _ = strconv.Atoi(sidType[1])
	}

	ssl, _ := strconv.ParseBool(apiConfig.Data.APIServerSSL)
	schema := "http://"
	if ssl {
		schema = "https://"
	}

	ss_service_url := schema + apiConfig.Data.APIServerDomain + "/getRequestData"
	if apiConfigParsedData.LogsEnabled == true {
		glog.V(2).Info("[ShieldSquare:info] --> ss service url : ", ss_service_url)
	}
	ip, Port, _ := net.SplitHostPort(req.RemoteAddr)
	userIP := ""
	splitIP := ""
	if apiConfigParsedData.LogsEnabled == true {
		glog.V(2).Info("[ShieldSquare:info] --> user ip : ", userIP)
	}

	if strings.Contains(apiConfig.Data.IPAddress, "Auto") {
		userIP = strings.Trim(net.IP.String(net.ParseIP(ip)), ":")
	} else {
		IPIndex, _ := strconv.Atoi(apiConfig.Data.IPIndex)
		userIP = req.Header.Get(apiConfig.Data.IPAddress)
		if userIP != "" {
			userIP = strings.Replace(userIP, " ", "", -1)
			splitIP = SplitIP(userIP, IPIndex)
		} else {
			userIP = strings.Trim(net.IP.String(net.ParseIP(ip)), ":")
		}
	}
	if splitIP == "" {
		splitIP = userIP
	}

	cookieA, errA := req.Cookie("__uzma")
	cookieB, errB := req.Cookie("__uzmb")
	cookieC, errC := req.Cookie("__uzmc")
	cookieD, errD := req.Cookie("__uzmd")

	if call_type == MOBILE {
		cookieE, errE := req.Cookie("__uzme")
		//if cookie not present
		if errE != nil {
			//create new cookie
			uuid, _ := uuid.NewV4()
			ssJsonObj.Uzme = uuid.String()
			E := http.Cookie{Name: "__uzme", Value: ssJsonObj.Uzme, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: apiConfigParsedData.HTTPOnly}
			http.SetCookie(w, &E)
		} else {
			ssJsonObj.Uzme = cookieE.Value
		}
	}

	var IsDigit = regexp.MustCompile(`^[0-9]+$`).MatchString

	cookieAbsent := false
	cookieTampered := false
	uzmc_val := ""
	uzmcCounter := 0

	if errA != nil || errB != nil || errC != nil || errD != nil {
		cookieAbsent = true
		uzmc_val = GenerateUzmc(0)
		if apiConfigParsedData.LogsEnabled == true {
			glog.V(2).Info("[ShieldSquare:error] --> error while getting cookie : ")
		}
	} else {
		if len(cookieB.Value) != 10 || IsDigit(cookieB.Value) == false || len(cookieC.Value) < 12 || IsDigit(cookieC.Value) == false || len(cookieD.Value) != 10 || IsDigit(cookieD.Value) == false || len(cookieA.Value) != 36 {
			cookieTampered = true
			uzmc_val = GenerateUzmc(0)
		} else {
			uzmcSequence, _ := strconv.Atoi(cookieC.Value[5 : len(cookieC.Value)-5])
			uzmcCounter = (uzmcSequence - 7) / 3
			uzmc_val = GenerateUzmc(uzmcCounter)
		}
	}

	if cookieAbsent || cookieTampered {
		uuid, err := uuid.NewV4()
		if err != nil {
			if apiConfigParsedData.LogsEnabled == true {
				glog.V(2).Info("[ShieldSquare : error] --> uuid generation failed")
			}
		}

		ssJsonObj.Uzma = uuid.String()
		ssJsonObj.Uzmb = strconv.FormatInt(TimeNowSecs, 10)

		A := http.Cookie{Name: "__uzma", Value: ssJsonObj.Uzma, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: apiConfigParsedData.HTTPOnly}
		B := http.Cookie{Name: "__uzmb", Value: ssJsonObj.Uzmb, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: apiConfigParsedData.HTTPOnly}

		http.SetCookie(w, &A)
		http.SetCookie(w, &B)
	} else {
		ssJsonObj.Uzma = cookieA.Value
		ssJsonObj.Uzmb = cookieB.Value
	}
	ssJsonObj.Uzmc = uzmc_val
	ssJsonObj.Uzmd = strconv.FormatInt(TimeNowSecs, 10)

	C := http.Cookie{Name: "__uzmc", Value: ssJsonObj.Uzmc, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: apiConfigParsedData.HTTPOnly}
	D := http.Cookie{Name: "__uzmd", Value: ssJsonObj.Uzmd, Expires: Expiration, Secure: apiConfigParsedData.Secure, HttpOnly: apiConfigParsedData.HTTPOnly}

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
	ssJsonObj.Zpsbd8 = call_type
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

	ssJsonObj.Zpsbdt = apiServer.ConnectorID + " 5.2.1"

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
		glog.V(2).Info("[ShieldSquare:info] --> Body ", string(jsonObject))
	}
	fmt.Println(string(jsonObject))

	if apiConfig.Data.Mode == "Monitor" && apiConfig.Data.AsyncPost == "True" {
		sendTime = time.Now().UnixNano() / int64(time.Millisecond)
		Async_SendReq2SS(ss_service_url, jsonObject)
		recTime = time.Now().UnixNano() / int64(time.Millisecond)
		respTime = recTime - sendTime

		ss_Resp = SS_service_resp{strconv.Itoa(ALLOW), "var __uzdbm_c = 2+2", ""}
	} else {
		sendTime = time.Now().UnixNano() / int64(time.Millisecond)
		ss_response := Sync_SendReq2SS(ss_service_url, jsonObject)
		recTime = time.Now().UnixNano() / int64(time.Millisecond)
		respTime = recTime - sendTime
		if ss_response != "" {
			json.Unmarshal([]byte(ss_response), &ss_Resp)
			ss_Resp = SS_service_resp{ss_Resp.Ssresp, ss_Resp.Dynamic_js, ss_Resp.BotCode}
			Resp, err := strconv.Atoi(ss_Resp.Ssresp)
			if Resp >= CAPTCHA && Resp <= BLOCK && err == nil && call_type != MOBILE {
				Query := getRedirectQueryParams(ssJsonObj, apiConfig.Data.SupportEmail, apiConfig.Data.RedirectDomain)
				Type := ""
				schema := "http://"
				if strings.Contains(apiConfig.Data.EndPointSSL, "True") {
					schema = "https://"
				}
				if ss_Resp.Ssresp == strconv.Itoa(CAPTCHA) && strings.Contains(apiConfig.Data.SSCaptchaEnabled, "True") {
					Type = "/captcha?"
					RedirUrl := schema + apiConfig.Data.RedirectDomain + Type + Query
					http.Redirect(w, req, RedirUrl, http.StatusTemporaryRedirect)
				}
				if ss_Resp.Ssresp == strconv.Itoa(BLOCK) && strings.Contains(apiConfig.Data.SSBlockEnabled, "True") {
					Type = "/block?"
					RedirUrl := schema + apiConfig.Data.RedirectDomain + Type + Query
					http.Redirect(w, req, RedirUrl, http.StatusTemporaryRedirect)
				}
			}

		}
	}
	if call_type == MOBILE {
		if (apiConfig.Data.SSCaptchaEnabled == "True" && ss_Resp.Ssresp == "2") || (apiConfig.Data.SSBlockEnabled == "True" && ss_Resp.Ssresp == "3") {
			w.Header().Add("_uzmcr", GetUzmcr(ss_Resp.Ssresp))
		}
		if apiConfig.Data.PostURL != "" {
			w.Header().Add("posturl", apiConfig.Data.PostURL)
		}
		if apiConfig.Data.TrkEvent != "" {
			w.Header().Add("trkevent", apiConfig.Data.TrkEvent)
		}
	}

	if apiConfigParsedData.SeverLogsEnabled {
		log := SIEM_JSON{ssJsonObj.Zpsbd6, ssJsonObj.Zpsbd7, ssJsonObj.Zpsbd4, ssJsonObj.Zpsbd3, ssJsonObj.Zpsbd5, ssJsonObj.Zpsbd9, respTime, errorDesc}
		logLevel := "debug"
		if apiConfig.Data.LogLevel != "" {
			logLevel = apiConfig.Data.LogLevel
		}
		printSIEM(log, logLevel)
	}

	glog.Flush()
	return json.Marshal(ss_Resp)

}

func Sync_SendReq2SS(ss_service_url string, jsonObject []byte) string {

	req, _ := http.NewRequest(http.MethodPost, ss_service_url, bytes.NewBuffer(jsonObject))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body))
		if err != nil {
			errorDesc = string(err.Error())
		}
		return string(body)
	} else {
		// Log proper error
		fmt.Println("Error")
		return ""
	}
}

func Async_SendReq2SS(ss_service_url string, jsonObject []byte) {

	req, _ := http.NewRequest(http.MethodPost, ss_service_url, bytes.NewBuffer(jsonObject))
	req.Header.Set("Content-Type", "application/json")

	go func() {
		resp, err := httpClient.Do(req)
		if err != nil {
			if apiConfigParsedData.LogsEnabled == true {
				errorDesc = string(err.Error())
				glog.V(2).Info("[ShieldSquare:error] --> async_post error ", err)
			}
		}
		if resp != nil {
			defer resp.Body.Close()
		}
	}()
}

func GenerateUzmc(uzmc_counter int) string {
	count := ((uzmc_counter + 1) * 3) + 7
	uzmc := strconv.Itoa(randomNum(10000, 99999)) + strconv.Itoa(count) + strconv.Itoa(randomNum(10000, 99999))
	return uzmc
}

func GeneratePid(sid string) string {
	b := strings.Split(sid, "-")
	s := strings.ToLower(strconv.FormatInt(int64(time.Now().Unix()), 16))
	return randomHex(10000, 65000) + randomHex(10000, 65000) + "-" + b[3] + "-" + reverseStr(s[len(s)-4:len(s)]) + "-" + randomHex(10000, 65000) + "-" + randomHex(10000, 65000) + randomHex(10000, 65000) + randomHex(10000, 65000)
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
	uuid, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return uuid.String()
}

func getRedirectQueryParams(ssJsonObj SSJsonObj, EmailID string, RedirDomain string) string {

	if !strings.Contains(RedirDomain, "validate.perfdrive.com") {
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
	Chars := "abcdefghijk@lmnop"
	CharDigits0 := "0123456789abcdef"
	CharDigits1 := "0123456abcdefghkizlmp"
	CharDigits2 := "pqrstuv23419@lmno"
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

	UserAgent := [5]string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/4.0 (Windows NT 5.1) AppleWebKit/535.7 (KHTML,like zeco) Chrome/33.0.1750.154 Safari/536.7",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1) Gecko/20100101 Firefox/39.0",
		"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
		"Chrome/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16",
	}
	ssa := GenerateUUID()
	ssb := RandomString(25, CharDigits1)
	ssc := url.QueryEscape(ssJsonObj.Zpsbd4)
	ssd := RandomString(15, Digits)
	sse := RandomString(15, Chars)
	ssf := RandomString(40, CharDigits0)
	ssg := GenerateUUID()
	ssh := GenerateUUID()
	ssi := ssJsonObj.Zpsbd2
	ssj := GenerateUUID()
	ssk := EmailID
	ssl := RandomString(12, Digits)
	ssm := RandomString(17, Digits) + UzmcSequence + RandomString(13, Digits)

	DecodeUrl, _ := url.QueryUnescape(ssJsonObj.Zpsbd4)
	InputDigest := ssJsonObj.Zpsbd1 + ssJsonObj.Zpsbd5 + DecodeUrl + UzmcSequence + ssJsonObj.Zpsbd2 + ssJsonObj.Zpsbd7 + EmailID + IPtoProcess
	Digest := sha1.Sum([]byte(InputDigest))
	DigestStr := hex.EncodeToString(Digest[:])

	ssn := RandomString(8, CharDigits0) + DigestStr[0:20] + RandomString(8, CharDigits0) + UzmaFirstPart + RandomString(5, CharDigits0)
	sso := RandomString(5, CharDigits0) + UzmaSeconPart + RandomString(8, CharDigits0) + DigestStr[20:40] + RandomString(8, CharDigits0)

	ssp := RandomString(10, Digits) + ssJsonObj.Uzmb[0:5] + RandomString(5, Digits) + ssJsonObj.Uzmd[5:5] + RandomString(10, Digits)
	ssq := RandomString(7, Digits) + ssJsonObj.Uzmb[5:10] + RandomString(9, Digits) + ssJsonObj.Uzmd[5:10] + RandomString(15, Digits)

	ssr := base64.StdEncoding.EncodeToString([]byte(IPtoProcess))

	sss := UserAgent[randomNum(1, 5)]
	sst := ssJsonObj.Zpsbd7
	ssu := UserAgent[randomNum(1, 5)]

	ssv := RandomString(15, CharDigits2)
	ssw := ssJsonObj.Zpsbd5
	ssx := RandomString(15, Digits)
	ssy := RandomString(40, Chars)
	ssz := RandomString(15, CharDigits0)

	query := "ssa=" + ssa + "&ssb=" + ssb + "&ssc=" + ssc + "&ssd=" + ssd + "&sse=" + sse +
		"&ssf=" + ssf + "&ssg=" + ssg + "&ssh=" + ssh + "&ssi=" + ssi + "&ssj=" + ssj +
		"&ssk=" + ssk + "&ssl=" + ssl + "&ssm=" + ssm + "&ssn=" + ssn + "&sso=" + sso +
		"&ssp=" + ssp + "&ssq=" + ssq + "&ssr=" + ssr + "&sss=" + sss + "&sst=" + sst +
		"&ssu=" + ssu + "&ssv=" + ssv + "&ssw=" + ssw + "&ssx=" + ssx + "&ssy=" + ssy +
		"&ssz=" + ssz

	return query

}

func printSIEM(siem_json SIEM_JSON, log_level string) {
	siemLog, err := json.Marshal(siem_json)
	if err != nil {
		glog.V(2).Info("[ShieldSquare:error] --> Error while creating SIEM Log")
	}
	if strings.ToLower(log_level) == "info" {
		glog.V(2).Info("[ShieldSquare:info] --> SIEM Log : \n", string(siemLog))
	} else if strings.ToLower(log_level) == "debug" {
		glog.V(2).Info("[ShieldSquare:debug] --> SIEM Log : \n", string(siemLog))
	} else if strings.ToLower(log_level) == "warn" {
		glog.V(2).Info("[ShieldSquare:warn] --> SIEM Log : \n", string(siemLog))
	} else if strings.ToLower(log_level) == "error" {
		glog.V(2).Info("[ShieldSquare:error] --> SIEM Log : \n", string(siemLog))
	} else if strings.ToLower(log_level) == "notice" {
		glog.V(2).Info("[ShieldSquare:notice] --> SIEM Log : \n", string(siemLog))
	}

}
