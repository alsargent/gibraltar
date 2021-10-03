package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func connectToDatabase() {


	return

}

func siteUp(domain string, protocol string) bool {
	one := []byte{}
	conn, err := net.Dial("tcp", domain+":"+protocol)
	if err == nil {
		conn.SetReadDeadline(time.Now())
		if _, err := conn.Read(one); err == io.EOF {
			conn.Close()
			conn = nil
			return false
		}
		return true
	}
	return false
}

func evalStatus(statusCode int, url string) {
	switch {
	case statusCode < 200:
		fmt.Printf("\nError: Illegal status code when getting URL %v. Statuscode: %v.\n", url, statusCode)
		// Todo: log & upsert appropriate row in database
		// Downtime, since error at server end.
	case statusCode == 200:
		fmt.Printf(".")
		// Todo: log & upsert appropriate row in database
		// Uptime, since successful request.
	case 200 < statusCode && statusCode < 300:
		fmt.Printf("\nSuccess: accessed URL %v. Statuscode: %v.\n", url, statusCode)
		// Todo: log & upsert appropriate row in database
		// Uptime, since successful request.
	case 300 <= statusCode && statusCode < 400:
		fmt.Printf("\nError: Too many redirects when getting URL %v. Statuscode: %v.\n", url, statusCode)
		// Todo: log & upsert appropriate row in database
		// Downtime, since too many redirects at server end. This is why we set a generous redirect limit.
		// In practice, we should never get here, but rather timeout when we get a lot of redirects.
	case 400 <= statusCode && statusCode < 500:
		fmt.Printf("\nError: Client-side error when getting URL %v. Statuscode: %v.\n", url, statusCode)
		// Todo: log & upsert appropriate row in database.
		// Not downtime, since the error is at our end.
	case 500 <= statusCode && statusCode < 600:
		fmt.Printf("\nError: Server failure when getting URL %v. Statuscode: %v.\n", url, statusCode)
		// Todo: log & upsert appropriate row in database
		// Downtime, since error at server end.
	case 600 <= statusCode:
		fmt.Printf("\nError: Illegal status code when getting URL %v. Statuscode: %v.\n", url, statusCode)
		// Todo: log & upsert appropriate row in database
		// Downtime, since error at server end. This would be a bizarre issue.
	}
}

func ping(urlString string) {
	const (
		expiry       = 20 // When our http get request times out, in seconds
		maxRedirects = 20 // Max # of http 3xx redirects we allow. Chrome's max is 20.
		// To reduce our chances of being classified as a bot: HTTP header fields from a Chrome browser on Windows 10, running incognito, early 2018.
		accept         = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
		acceptEncoding = "gzip, deflate, br"
		acceptLanguage = "n-US,en;q=0.9"
		connection     = "keep-alive"
		userAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36"
	)

	// Parse the URL to get the domain
	u, err := url.Parse(urlString)
	if err != nil {
		fmt.Printf("\nError: cannot parse URL %v. Error: %v\n", urlString, err.Error())
		// Todo: log but don't upsert. Issue is at our end.
		return
	}
	domain := u.Hostname()
	protocol := u.Scheme

	// Check that the domain is reachable over http(s).
	if !siteUp(domain, protocol) {
		// Before jumping to conclusions, check if we can reach Google.
		if !siteUp("www.google.com", "http") {
			fmt.Print("Error: network is down\n")
			// Log this, but don't upsert into database. If Google isn't reachable, we assume issue is our end.
			return
		}
		fmt.Printf("\nError: cannot connect to domain %v over %v.\n", domain, protocol)
		// Todo: log & upsert appropriate row in database
		// Downtime since the entire domain is down.
		return
	}
	fmt.Printf(".") // Good news: domain is reachable. But no need to upsert here.

	// Setup our http client to timeout, and to follow a generous number of redirects.
	netClient := &http.Client{
		Timeout: time.Second * expiry,
		CheckRedirect: func() func(req *http.Request, via []*http.Request) error {
			redirects := 0
			return func(req *http.Request, via []*http.Request) error {
				if redirects > maxRedirects {
					return fmt.Errorf("stopped after %v redirects", maxRedirects)
				}
				redirects++
				return nil
			}
		}(),
	}

	// Create a request with a normal-looking user agent string
	req, err := http.NewRequest("GET", urlString, nil)
	if err != nil {
		fmt.Printf("\nError: Building request for URL %v. Error: %v\n", urlString, err.Error())
		// Todo: log but don't upsert. Issue is likely in our Go environment setup.
		return
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Encoding", acceptEncoding)
	req.Header.Set("Accept-Language", acceptLanguage)
	req.Header.Set("Connection", connection)
	req.Header.Set("User-Agent", userAgent)

	// Then do an HTTP GET on the URL
	resp, err := netClient.Do(req)

	if resp == nil {
		fmt.Printf("\nError: response from URL %v is nil\n", urlString)
		// Todo: log & upsert appropriate row in database
		// Downtime, since a null response.
		return
	}

	if err != nil {
		// We can get here via a timeout, or too many redirects.
		// Switch from GET to HEAD to see if that fixes things.
		fmt.Printf("\nSwitching to HEAD request for URL %v\n", urlString)
		req.Method = "HEAD"
		// Do an HTTP HEAD on the URL
		resp, err := netClient.Do(req)

		if err != nil {
			errorString := strings.ToLower(err.Error())
			switch {

			// Timeout error
			case strings.Contains(errorString, "client.timeout exceeded while"):
				fmt.Printf("\nError: When HEADing URL %v, %v.\n", urlString, errorString)
			// Todo: log & upsert appropriate row in database. We should have our own numbering scheme for these errors.

			// Too many redirects
			case strings.Contains(errorString, "stopped after") && strings.Contains(errorString, "redirects"):
				fmt.Printf("\nError: When HEADing URL %v, %v.\n", urlString, errorString)
				// Todo: log & upsert appropriate row in database. We should have our own numbering scheme for these errors.

			// Some other error
			default:
				fmt.Printf("\nError: When HEADing URL %v, %v.\n", urlString, errorString)
				// Todo: log & upsert appropriate row in database. We should have our own numbering scheme for these errors.
			}
			return
		}

		// HEAD didn't result in an error, so evaluate the HTTP return code.
		evalStatus(resp.StatusCode, urlString)
		return
	}

	evalStatus(resp.StatusCode, urlString)
}

func main() {

	links := []string{
		"https://www.leadfeeder.com", "https://app.leadfeeder.com/login", "https://app.leadfeeder.com/users/forgotpassword",
		"https://www.salesforce.com", "https://login.salesforce.com/", "https://login.salesforce.com/secur/forgotpassword.jsp?locale=us&lqs=&display=touch",
		"https://www.office.com/", "https://login.microsoftonline.com", "https://login.microsoftonline.com/common/oauth2/authorize?client_id=4345a7b9-9a63-4910-a426-35363201d503&response_mode=form_post&response_type=code+id_token&scope=openid+profile&state=OpenIdConnect.AuthenticationProperties%3dL42y1YGpccBb3o6clKBnMemgdkqkUo9nOXzvuk-V_7zpRRVDudl889hdSDy1WRL7J3-ffKsVTrb4CK5D4rvCwqb5xTK4ViVW8nrU2qy_7ISNr9g-rTwLB9-XQXP51Zw7&nonce=636502644545646914.YTg1OGMyYzYtNGM0ZS00ZjViLThiOTItNGUyZDdjODk2OTNiZDIzMTkwZjgtMDNiMy00ZTFjLTgzODktZjA0OGQzOGQ5N2E4&redirect_uri=https%3a%2f%2fwww.office.com%2f&ui_locales=en-US&mkt=en-US&client-request-id=e6195f55-bb2e-4231-9dea-6b9cc65a1b69",
		"https://www.box.com/", "https://account.box.com/", "https://account.box.com/login/reset",
		"https://aws.amazon.com/", "https://signin.aws.amazon.com/signin?redirect_uri=https%3A%2F%2Fconsole.aws.amazon.com%2Fconsole%2Fhome%3Fstate%3DhashArgs%2523%26isauthcode%3Dtrue&client_id=arn%3Aaws%3Aiam%3A%3A015428540659%3Auser%2Fhomepage&forceMobileApp=0",
		"https://gsuite.google.com/", "https://accounts.google.com/signin/v2/identifier?service=CPanel&passive=1209600&cpbps=1&continue=https%3A%2F%2Fadmin.google.com%2FSacredsf.org%2FDashboard&followup=https%3A%2F%2Fadmin.google.com%2FSacredsf.org%2FDashboard&skipvpage=true&flowName=GlifWebSignIn&flowEntry=ServiceLogin", "https://accounts.google.com/signin/v2/usernamerecovery?service=CPanel&passive=1209600&cpbps=1&continue=https%3A%2F%2Fadmin.google.com%2FSacredsf.org%2FDashboard&followup=https%3A%2F%2Fadmin.google.com%2FSacredsf.org%2FDashboard&skipvpage=true&flowName=GlifWebSignIn&flowEntry=ServiceLogin",
		"https://www.concur.com/", "https://www.concursolutions.com/", "https://www.concursolutions.com/profile/send_password_hint.asp",
		"https://www.atlassian.com/software/jira", "https://id.atlassian.com/login", "https://id.atlassian.com/login/resetpassword",
		"https://slack.com/", "https://slack.com/signin",
		"https://www.zendesk.com/", "https://www.zendesk.com/login/#support", "https://www.zendesk.com/login/#loginReminder",
		"https://www.adp.com/", "https://www.adp.com/logins.aspx",
		"https://www.dropbox.com/", "https://www.dropbox.com/", "https://www.dropbox.com/forgot?email_from_login=",
		"https://www.docusign.com/", "https://account.docusign.com/#/username", "https://www.docusign.net/Member/MemberForgotPassword.aspx?accountServerRedirect=%2Foauth%2Fauth%2F",
		"https://www.webex.com/", "https://signin.webex.com/collabs/auth", "https://idbroker.webex.com/idb/saml2/jsp/doSSO.jsp#",
		"https://www.atlassian.com/software/confluence", "https://id.atlassian.com/login?application=mac&continue=https://my.atlassian.com", "https://id.atlassian.com/login/resetpassword?application=mac&continue=https://my.atlassian.com",
		"https://meraki.cisco.com/", "https://account.meraki.com/secure/login/dashboard_login", "https://account.meraki.com/login/reset_password",
		"https://www.linkedin.com/", "https://www.linkedin.com/m/login/", "https://www.linkedin.com/uas/request-password-reset",
		"https://www.servicenow.com", "https://hi.service-now.com/cms/login.do", "https://hi.service-now.com/$pwd_reset.do?sysparm_url=ss_default",
		"https://www.gotomeeting.com/", "https://authentication.logmeininc.com/login?service=https%3A%2F%2Fauthentication.logmeininc.com%2Foauth%2Fauthorize%3Fclient_id%3Db5821983-e640-42b4-86cd-5e7efadcc8f0%26redirect_uri%3Dhttps%253A%252F%252Fglobal.gotomeeting.com%26response_type%3Dtoken%26state%3D&theme=g2m", "https://authentication.logmeininc.com/pwdrecovery/?service=https://authentication.logmeininc.com/oauth/authorize?client_id%3Db5821983-e640-42b4-86cd-5e7efadcc8f0%26redirect_uri%3Dhttps%253A%252F%252Fglobal.gotomeeting.com%26response_type%3Dtoken%26state%3D&loginTheme=g2m",
		"https://twitter.com/", "https://twitter.com/login", "https://twitter.com/account/begin_password_reset",
		"https://www.godaddy.com/", "https://sso.godaddy.com/", "https://sso.godaddy.com/v1/account/reset?app=account&realm=idp&path=/products",
		"http://www.adobe.com/creativecloud.html", "https://adobeid-na1.services.adobe.com/renga-idprovider/pages/login?callback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fadobeid%2Fadobedotcom2%2FAdobeID%2Ftoken%3Fredirect_uri%3Dhttps%253A%252F%252Fwww.adobe.com%252Fcreativecloud.html%2523from_ims%253Dtrue%2526old_hash%253D%2526api%253Dauthorize&client_id=adobedotcom2&scope=creative_cloud%2CAdobeID%2Copenid%2Cgnav%2Cread_organizations%2Cadditional_info.projectedProductContext%2Csao.ACOM_CLOUD_STORAGE%2Csao.stock%2Csao.cce_private%2Cadditional_info.roles&denied_callback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fdenied%2Fadobedotcom2%3Fredirect_uri%3Dhttps%253A%252F%252Fwww.adobe.com%252Fcreativecloud.html%2523from_ims%253Dtrue%2526old_hash%253D%2526api%253Dauthorize%26response_type%3Dtoken&display=web_v2&relay=462eaf24-34bc-4ed5-be46-8eda20573ffb&locale=en_US&flow_type=token&idp_flow_type=login", "https://adobeid-na1.services.adobe.com/renga-idprovider/pages/start_forgot_password?client_id=adobedotcom2&callback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fadobeid%2Fadobedotcom2%2FAdobeID%2Ftoken%3Fredirect_uri%3Dhttps%253A%252F%252Fwww.adobe.com%252Fcreativecloud.html%2523from_ims%253Dtrue%2526old_hash%253D%2526api%253Dauthorize%26scope%3Dcreative_cloud%252CAdobeID%252Copenid%252Cgnav%252Cread_organizations%252Cadditional_info.projectedProductContext%252Csao.ACOM_CLOUD_STORAGE%252Csao.stock%252Csao.cce_private%252Cadditional_info.roles&denied_callback=https%3A%2F%2Fims-na1.adobelogin.com%2Fims%2Fdenied%2Fadobedotcom2%3Fredirect_uri%3Dhttps%253A%252F%252Fwww.adobe.com%252Fcreativecloud.html%2523from_ims%253Dtrue%2526old_hash%253D%2526api%253Dauthorize%26response_type%3Dtoken&display=web_v2&locale=en_US&relay=462eaf24-34bc-4ed5-be46-8eda20573ffb&flow=true&flow_type=token&idp_flow_type=login&s_account=adbims%2Cadbadobenonacdcprod",
		"https://github.com/", "https://github.com/login", "https://github.com/password_reset",
		"https://www.fedex.com/en-us/home.html", "https://www.fedex.com/en-us/home.html", "https://www.fedex.com/fcl/web/jsp/forgotPassword.jsp?appName=fclfsm&locale=us_en&step3URL=https%3A%2F%2Fwww.fedex.com%2Fshipping%2FshipEntryAction.do%3Fmethod%3DdoRegistration%26link%3D1%26locale%3Den_US%26urlparams%3Dus%26sType%3DF&returnurl=https%3A%2F%2Fwww.fedex.com%2Fshipping%2FshipEntryAction.do%3Fmethod%3DdoEntry%26link%3D1%26locale%3Den_US%26urlparams%3Dus%26sType%3DF&programIndicator=0",
		"https://www.workday.com/en-us/homepage.html", "https://www.workday.com/en-us/signin.html", "http://workdayinc.force.com/customercenter/WorkdayCustomerPortalForgotUserName",
		"http://www.netsuite.com/portal/home.shtml", "https://system.netsuite.com/pages/customerlogin.jsp?country=US&vid=yj0Gnu5HAhKTcxsL&chrole=17&ck=zjj6Vu5HAhCTc7kw&cktime=149486&promocode=&promocodeaction=overwrite", "https://system.netsuite.com/app/login/preparepwdreset.nl",
		"https://www.akamai.com/", "https://control.akamai.com/apps/auth/?TARGET_URL=Y29udHJvbC5ha2FtYWkuY29tL2hvbWVuZy92aWV3L21haW4=#/login", "https://control.akamai.com/EdgeAuth/RecoveryServlet?r=RESET_PASSWORD",
		"http://www.birlasoft.com/", "https://my.birlasoft.com/dana-na/auth/url_default/welcome.cgi",
		"https://www.athenahealth.com/", "https://athenanet.athenahealth.com/1/1/login.esp", "https://athenanet.athenahealth.com/1/1/resetpassword.esp?LOGINURL=",
		"https://www.zoho.com/", "https://accounts.zoho.com/signin?servicename=ZohoHome&serviceurl=https://home.zoho.com&signupurl=https://www.zoho.com/signup.html", "https://accounts.zoho.com/password?servicename=ZohoHome&hide_reg_link=false&service_language=en&serviceurl=https%3A%2F%2Fhome.zoho.com",
		"https://www.tableau.com/", "https://identity.idp.tableau.com/login?client=EyTZIwfn9S3ebNMyDu5N4fq911RlIoat&protocol=oauth2&redirect_uri=https%3A%2F%2Fid.tableau.com%2Fcallback&response_type=token%20id_token&scope=openid%20email&audience=https%3A%2F%2Fid.tableau.com%2Fapi%2Fv4%2F&lng=en-us&nonce=fiXnnK4hC.H4TRewjb7jSUzpwsoDCreg&auth0Client=eyJuYW1lIjoiYXV0aDAuanMiLCJ2ZXJzaW9uIjoiOS4xLjAifQ%3D%3D&state=T7vlpkGBtptctx3jOMHzSo3Lzo8KhT3K", "https://id.tableau.com/resetPassword?clientId=EyTZIwfn9S3ebNMyDu5N4fq911RlIoat",
		"https://www.ariba.com/", "https://service.ariba.com/Buyer.aw/128490032/aw?awh=r&awssk=Ix2TVGfJ&dard=1", "https://service.ariba.com/Authenticator.aw/ad/forgotPassword",
		"https://www.splunk.com/", "https://www.splunk.com/page/sign_up/cloud_trial", "https://www.splunk.com/page/lost_password",
		"http://www.cvent.com/", "https://app.cvent.com/Subscribers/MobileLogin?ReturnUrl=%2fsubscribers%2fdefault.aspx", "https://app.cvent.com/subscribers/mobilelogin/ForgotLogin",
		"https://www.eclinicalworks.com/", "https://my.eclinicalworks.com/eCRM/jsp/index.jsp", "https://my.eclinicalworks.com/eCRM/jsp/forgotPassword.jsp",
		"https://www.criteo.com/", "https://marketing.criteo.com/Login?redirectTo=%252FHome", "https://account.criteo.com/auth/XUI/criteo-login/#/reset-password?realm=~2Fcriteo",
		"https://sentry.com/", "https://login.sentry.com", "https://login.sentry.com/dialog/DisplayForgotPassword;jsessionid=C490BCDD257B4D9ADE8DB6D185F5EFC0?continueURL=",
		"https://www.veeam.com/", "https://login.veeam.com/oauth?client_id=nXojRrypJ8&redirect_uri=https%3A%2F%2Fwww.veeam.com%2Fservices%2Fauthentication%2Fredirect_url&response_type=code&scope=profile&state=%7B%22finalRedirectLocation%22%3A%22https%3A%2F%2Fwww.veeam.com%2F%22%7D", "https://login.veeam.com/restore",
		"https://www.logmein.com/", "https://accounts.logme.in/login.aspx?clusterid=02&returnurl=https%3A%2F%2Fsecure.logmein.com%2Ffederated%2Floginsso.aspx&headerframe=https%3A%2F%2Fsecure.logmein.com%2Ffederated%2Fresources%2Fheaderframe.aspx&productframe=https%3A%2F%2Fsecure.logmein.com%2Fcommon%2Fpages%2Fcls%2Flogin.aspx&lang=en-US&skin=logmein&regtype=R&trackingproducttype=2", "https://accounts.logme.in/forgotpassword.aspx?clusterid=02&returnurl=https%3A%2F%2Fsecure.logmein.com%2Ffederated%2Floginsso.aspx&headerframe=https%3A%2F%2Fsecure.logmein.com%2Ffederated%2Fresources%2Fheaderframe.aspx&productframe=https%3A%2F%2Fsecure.logmein.com%2Fcommon%2Fpages%2Fcls%2Flogin.aspx&lang=en-US&regtype=R&trackingproducttype=2&skin=logmein",
		"https://www.hubspot.com/", "https://app.hubspot.com/login?_ga=2.4928245.797146109.1514676965-1032433412.1514676965", "https://app.hubspot.com/login/forgot/?email=",
		"https://squareup.com/", "https://squareup.com/login", "https://squareup.com/login",
		"https://www.shopify.com/", "https://www.shopify.com/login", "https://www.shopify.com/forgot-password",
		"https://www.ringcentral.com/", "https://service.ringcentral.com/#/enterCredential", "https://service.ringcentral.com/#/resetPassword/number/",
		"http://synchronoss.com/", "https://synchronossmessaging.force.com/OpenwaveMessagingLogin", "https://tfa.synchronoss.com/SecureAuth9/",
		"https://www.cornerstoneondemand.com/", "https://clients.csod.com/client/clients/default.aspx",
		"https://www.aspect.com/",
		"https://www.palantir.com/", "https://javadoc.palantir.com/auth",
		"http://web.mycompas.com/", "https://www.mycompas.com/globallogin.aspx",
		"https://www.wix.com/", "https://users.wix.com/signin?loginDialogContext=login&referralInfo=HEADER&postLogin=https:%2F%2Fwww.wix.com%2Fmy-account%2Fsites%2F&postSignUp=https:%2F%2Fwww.wix.com%2Fnew%2Fvertical%3FreferralAdditionalInfo%3Dheader&originUrl=https:%2F%2Fwww.wix.com%2F",
		"https://www.successfactors.com/en_us.html", "https://performancemanager4.successfactors.com/login#/companyEntry",
		"https://www.xero.com/us/", "https://login.xero.com/", "https://login.xero.com/ForgottenPassword",
		"https://www.meltwater.com/", "https://www.meltwater.com/login/",
		"https://www.tangoe.com/", "https://cp.tangoe.com/Login.aspx?ReturnUrl=%2f", "https://cp.tangoe.com/Login.aspx?ReturnUrl=%2f",
		"https://www.paylocity.com/", "https://access.paylocity.com/", "https://access.paylocity.com/ForgotPassword",
		"https://www.proofpoint.com/us", "https://proofpointcommunities.force.com/community/PPSupCommunityLogin?ec=302&startURL=%2Fcommunity%2Fs%2F", "https://proofpointcommunities.force.com/community/PPSup_ForgotPassword",
		"http://www.skillsoft.com/", "http://www.skillsoft.com/skillport-login.asp",
		"http://paycom.com/", "https://www.paycomonline.net/v4/cl/cl-login.php",
		"https://www.cloudera.com/", "https://sso.cloudera.com/", "https://sso.cloudera.com/forgotten-password.html",
		"http://www.activenetwork.com/",
		"https://www.mdsol.com/en", "https://www.imedidata.com/eng/forgot_password/new",
		"https://www.sprinklr.com/", "https://app.sprinklr.com/ui/login", "https://app.sprinklr.com/ui/login",
		"https://www.broadsoft.com/", "https://xchange.broadsoft.com/user/login", "https://xchange.broadsoft.com/user/password",
		"https://www.appdynamics.com/", "https://login.appdynamics.com/sso/authenticate/?site=corp&target=https://www.appdynamics.com/", "https://login.appdynamics.com/accounts/forgotpassword/",
		"https://www.qualtrics.com/", "https://www.qualtrics.com/login/", "https://login.qualtrics.com/login?path=%2FControlPanel%2F&product=ControlPanel#",
		"https://spscommerce.com/", "https://portal.hosted-commerce.net/sps/", "https://portal.hosted-commerce.net/portal/securityhelp/lostPassword.jsp",
		"https://www.vertafore.com/", "https://sso.identity.vertafore.com/adfs/ls/?wa=wsignin1.0&wtrealm=https%3a%2f%2fplatform.vertafore.com%2f&wctx=rm%3d0%26id%3dpassive%26ru%3d%252f&wct=2017-12-31T22%3a48%3a34Z", "https://vim.identity.vertafore.com/VIM/ForgotPassword.aspx",
		"https://www.benefitfocus.com/", "https://secure2.benefitfocus.com/go/bfi/?_ga=2.264624073.793861579.1514760581-1175372971.1514760581",
	}

	// Connect to database

	for {
		// Do this forever.
		for _, link := range links {
			ping(link)
		}
	}
}
