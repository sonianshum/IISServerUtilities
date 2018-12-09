namespace Authenticator.HttpModule
{
    #region using statements
    using System;
    using System.Collections.Generic;
    using System.Web;
    using System.Linq;
    using System.Xml.Linq;
    using System.Globalization;
    using Authenticator.HttpModule.Properties;
    #endregion

    public class AuthenticationModule : IHttpModule
    {
        //Default virtual directory path for HTTP module 
        private static readonly string HttpModulePath = Resources.ModulePath;
        private static readonly string HttpModuleSettingFileName = Resources.ModuleSettingFileName;
        private bool _authentication;
        private static IList<string> _authApplications = null;

        private static IList<string> Applications
        {
            get
            {
                if (_authApplications == null)
                {
                    string filPath = string.Concat(ReadRegistry.InstallationPath, HttpModuleSettingFileName);

                    XElement xelement = XElement.Load(filPath);
                    var applications = xelement.Elements().Descendants().Where(x => x.Name.LocalName.Equals("VirtualPath"));

                    if (applications != null)
                    {
                        _authApplications = new List<string>();
                        foreach (var app in applications)
                        {
                            _authApplications.Add(app.Value);
                        }
                    }
                }
                return _authApplications;
            }
        }
        /// <summary>
        /// Read registry key & values or load default values otherwise
        /// </summary>
        private static IDictionary<string, string> AuthSettingKeys => ReadRegistry.SessionKeys;

        /// <summary>
        /// Initializes a module and prepares it to handle requests.
        /// </summary>
        /// <param name="context">
        ///     An System.Web.HttpApplication that provides access to the methods, properties,
        ///     and events common to all application objects within an ASP.NET application
        /// </param>
        public void Init(HttpApplication context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!_authentication)
            {
                //context.PostAcquireRequestState += OnPostAcquireRequestState;
                context.BeginRequest += OnPostAcquireRequestState;
            }
        }

        /// <summary>
        /// Disposes of the resources (other than memory) used by the module that implements
        /// </summary>
        public void Dispose()
        {
            _authentication = false;
        }

        /// <summary>
        /// Function to filter the incoming request based on the ACL present in Applications
        /// </summary>
        /// <returns></returns>
        private static bool CheckAuthenticationRequest(HttpContext context)
        {
            Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.CheckingUrl, context.Request.ApplicationPath));

            var isExist = false;
            //Check the Path & Query String : just take the Path and verify
            if (context.Request.ApplicationPath != null)
            {
                if (context.Request.Url.PathAndQuery.Contains("/favicon.ico"))
                {
                    return false;
                }
                //its a root node
                if (context.Request.ApplicationPath.Equals("/"))
                {
                    return true;
                }
                if ((Applications != null) && (Applications.Count > 0))
                {
                    var currentRequest = context.Request.ApplicationPath;
                    isExist = _authApplications.Any(x => x.Equals(currentRequest));
                }

                Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.IsProtected, isExist));

                return isExist;
            }
            return false;
        }

        /// <summary>
        /// Event handlers for the current request.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnPostAcquireRequestState(object sender, EventArgs e)
        {
            var application = (HttpApplication)sender;
            var context = application.Context;

            //1. Check if URL is protected
            if (CheckAuthenticationRequest(context) && !CheckAuthCookie(application))
            {
                RewriteUnauthorizedResponse(context);
            }
        }

        /// <summary>
        /// Function to validate the AuthCookie value
        /// </summary>
        /// <param name="application"></param>
        /// <returns></returns>
        private static bool CheckAuthCookie(HttpApplication application)
        {
            Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.CheckAuthCookie));

            //1. Cookie with Name faAuth doesnt exist
            var cookieName = application.Request.Cookies.Get(Resources.ModuleAuthCookieName);

            //2. Extract cookie value and return if null
            if (string.IsNullOrEmpty(cookieName?.Value))
            {
                Logger.DebugFormat(Resources.NoCookiePresent);
                return false;
            }

            try
            {
                //3. Decrypt cookie value and validate the value
                var cookieValue = CryptoHelper.Decrypt(cookieName.Value);

                Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.DecryptCookieValue, cookieValue));
                if (string.IsNullOrEmpty(cookieValue) || !cookieValue.StartsWith(Resources.ModuleCookieValuePrefix))
                {
                    Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.InvalidAuthCookiePresent, cookieName.Value));
                    return false;
                }

                //4. Extract and refresh cookie data
                if (!RefreshCookie(application, cookieValue))
                {
                    //invalid cookie
                    return false;
                }
                return true;
            }
            catch (ArgumentNullException exception)
            {
                Logger.ErrorFormat(string.Format(CultureInfo.CurrentCulture, Resources.ErrorDecryptingCookieData, exception.Message));
                return false;
            }
            catch (ArgumentOutOfRangeException exception)
            {
                Logger.ErrorFormat(string.Format(CultureInfo.CurrentCulture, Resources.ErrorDecryptingCookieData, exception.Message));
                return false;
            }
            catch (Exception exception)
            {
                Logger.ErrorFormat(string.Format(CultureInfo.CurrentCulture, Resources.ErrorDecryptingCookieData, exception.Message));
                return false;
            }
        }

        /// <summary>
        /// Function to refresh cookie
        /// </summary>
        /// <param name="application"></param>
        /// <param name="cookieValue"></param>
        /// <returns></returns>
        private static bool RefreshCookie(HttpApplication application, string cookieValue)
        {
            try
            {
                //Split cookie value from : char and get the timeout
                //1 : Authenticate, 2 : datetime encrypt, 3 = excrypt username
                var cookieKeyValues = cookieValue.Split(':');
                if (cookieKeyValues.Length < 0)
                {
                    Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.InvalidAuthCookiePresent, cookieValue));
                    return false;
                }

                string timeout;

                if (string.IsNullOrEmpty(cookieKeyValues[1]))
                {
                    Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.InvalidAuthCookiePresent, cookieKeyValues[1]));
                    return false;
                }

                //convert back datetime HEX vale to datetime format
                var cookiedateTime = new DateTime(Convert.ToInt64(cookieKeyValues[1], 16));
                TimeSpan? span = DateTime.Now.Subtract(cookiedateTime);

                Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.TimespanDifference, span));

                if (AuthSettingKeys.TryGetValue(Resources.ModuleCookieIdleTimeout, out timeout))
                {
                    //1. cookie expired
                    if (span.Value.TotalSeconds >= Convert.ToInt16(timeout))
                    {
                        Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.AuthCookieExpired, cookieKeyValues[1]));
                        return false;
                    }
                    //2. refresh cookie with new encrypted  datatime 
                    if (span.Value.TotalSeconds > Convert.ToInt16(timeout) / 2)
                    {
                        Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.AuthCookieRefresh));

                        //encrypt entire string in format AuthPRefix : datatime : username (if exist)
                        var newCookieData =
                            CryptoHelper.Encrypt(string.Concat(Resources.ModuleCookieValuePrefix, ":",
                                DateTime.Now.Ticks.ToString("X2"), ":", cookieKeyValues[2]));

                        Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.SetAuthCookieData, string.Concat(Resources.ModuleCookieValuePrefix, DateTime.Now, ":", cookieKeyValues[2])));

                        //add cookie in header
                        application.Context.Response.Headers.Add(Resources.ModuleAuthCookieName, newCookieData);
                        application.Context.Response.Cookies.Add(new HttpCookie(Resources.ModuleAuthCookieName,
                            newCookieData));
                    }
                }
            }
            catch (ArgumentNullException exception)
            {
                Logger.ErrorFormat(string.Format(CultureInfo.CurrentCulture, Resources.ErrorReadingAuthCookie, exception.Message));
                return false;
            }
            catch (Exception exception)
            {
                Logger.ErrorFormat(string.Format(CultureInfo.CurrentCulture, Resources.ErrorReadingAuthCookie, exception.Message));
                return false;
            }
            return true;
        }

        private static void RewriteUnauthorizedResponse(HttpContext context)
        {
            ClearResponse(context);
            IssueAuthenticationChallenge(context);
        }

        private static void IssueAuthenticationChallenge(HttpContext context)
        {
            Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.RewriteRequest));

            if (!context.Request.Path.Contains(HttpModulePath + "/"))
            {
                var requestPath = context.Request.Path;
                var pathandquery = context.Request.Url.PathAndQuery;

                //Check for root one site
                if (requestPath.Equals("/") || ((Applications != null) && (Applications.Any(x => x.Equals(requestPath)))))
                {
                    context.Response.Headers.Add(Resources.ModuleRequestPathCookieName, requestPath);
                    context.Response.Cookies.Add(new HttpCookie(Resources.ModuleRequestPathCookieName, requestPath));

                    Logger.ErrorFormat(string.Format(CultureInfo.CurrentCulture, Resources.SetRequestPathCookie, requestPath));
                }              
                else if (context.Request.ApplicationPath.Equals("/"))
                {
                    context.Response.Headers.Add(Resources.ModuleRequestPathCookieName, pathandquery);
                    context.Response.Cookies.Add(new HttpCookie(Resources.ModuleRequestPathCookieName, pathandquery));

                    Logger.ErrorFormat(string.Format(CultureInfo.CurrentCulture, Resources.SetRequestQueryString, pathandquery));
                }

                Logger.DebugFormat(string.Format(CultureInfo.CurrentCulture, Resources.RedirectTo));
                context.Response.Redirect(HttpModulePath, true);
            }
        }

        private static void ClearResponse(HttpContext context)
        {
            var response = context.Response;
            response.StatusCode = 200;
            response.StatusDescription = Resources.ModuleResponseStatusDescription;
            response.RedirectLocation = string.Empty;
            response.Clear();
        }
    }
}
