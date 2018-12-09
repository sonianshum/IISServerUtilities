namespace Authenticator.HttpModule
{

    #region using statements
    using System;
    using System.Diagnostics;
    using System.Globalization;
    using System.Reflection;
    using log4net;
    using System.IO;
    using Authenticator.HttpModule.Properties;
    #endregion

    /// <summary>
    /// HttpModule Logger class </summary>
    public static class Logger
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(AuthenticationModule));

        /// <summary>
        ///     Checks if this logger is enabled for the Debug level.
        /// </summary>
        public static bool IsDebugEnabled => Log.IsDebugEnabled;

        /// <summary>
        ///     Checks if this logger is enabled for the Error level.
        /// </summary>
        public static bool IsErrorEnabled => Log.IsErrorEnabled;

        /// <summary>
        ///     Checks if this logger is enabled for the Info level.
        /// </summary>
        public static bool IsInfoEnabled => Log.IsInfoEnabled;

        /// <summary>
        ///     Checks if this logger is enabled for the Warn level.
        /// </summary>
        public static bool IsWarnEnabled => Log.IsInfoEnabled;

        /// <summary>
        /// to initialize logger : log4net
        /// </summary>
        static Logger()
        {
            // Gets directory of installation folder path & log4net configuration
            var log4NetConfigDirectory = ReadRegistry.InstallationPath;
            var log4NetConfigFilePath = Path.Combine(log4NetConfigDirectory, Resources.Log4netConfigurationFileName);
            log4net.Config.XmlConfigurator.ConfigureAndWatch(new FileInfo(log4NetConfigFilePath));
        }

        /// <summary>
        ///     Log a message object with the Debug level.
        /// </summary>
        /// <param name="message">The message object to log.</param>
        public static void Debug(object message)
        {
            Log.Debug(message);
        }

        /// <summary>
        ///     Log a message object with the Debug level including the stack trace of the System.Exception passed as a parameter.
        /// </summary>
        /// <param name="message">The message object to log.</param>
        /// <param name="exception">The exception to log, including its stack trace.</param>
        public static void Debug(object message, Exception exception)
        {
            if (IsDebugEnabled)
            {
                Log.Debug(message, exception);
            }
        }

        /// <summary>
        ///     Logs a formatted message string with the Debug level.
        /// </summary>
        /// <param name="format">A String containing zero or more format items</param>
        /// <param name="args">An Object array containing zero or more objects to format</param>
        public static void DebugFormat(string format, params object[] args)
        {
            if (IsDebugEnabled)
            {
                Log.DebugFormat(CultureInfo.InvariantCulture, format, args);
            }
        }

        /// <summary>
        ///     Logs an Enter message
        /// </summary>
        public static void Enter()
        {
            DebugFormat(string.Format(CultureInfo.InvariantCulture, $"Enter: {GetCaller()}"));
        }

        /// <summary>
        ///     Logs an Enter message
        /// </summary>
        /// <param name="format">A String containing zero or more format items</param>
        /// <param name="args">An Object array containing zero or more objects to format</param>
        public static void Enter(string format, params object[] args)
        {
            var stackTrace = string.Format(CultureInfo.InvariantCulture, $"Enter: {GetCaller()} {format}");
            DebugFormat(stackTrace, args);
        }

        /// <summary>
        ///     Logs a message object with the Error level.
        /// </summary>
        /// <param name="message">The message object to log.</param>
        public static void Error(object message)
        {
            Log.Error(message);
        }

        /// <summary>
        ///     Log a message object with the Error level including the stack trace of the System.Exception passed as a parameter.
        /// </summary>
        /// <param name="message">The message object to log.</param>
        /// <param name="exception">The exception to log, including its stack trace.</param>
        public static void Error(object message, Exception exception)
        {
            Log.Error(message, exception);
        }

        /// <summary>
        ///     Logs a formatted message string with the Error level.
        /// </summary>
        /// <param name="format">A String containing zero or more format items</param>
        /// <param name="args">An Object array containing zero or more objects to format</param>
        public static void ErrorFormat(string format, params object[] args)
        {
            Log.ErrorFormat(CultureInfo.InvariantCulture, format, args);
        }

        /// <summary>
        ///     Logs an Exit message
        /// </summary>
        public static void Exit()
        {
            DebugFormat(string.Format(CultureInfo.InvariantCulture, $"Exit: {GetCaller()}"));
        }

        /// <summary>
        ///     Logs an Exit message
        /// </summary>
        /// <param name="format">A String containing zero or more format items</param>
        /// <param name="args">An Object array containing zero or more objects to format</param>
        public static void Exit(string format, params object[] args)
        {
            var stackTrace = string.Format(CultureInfo.InvariantCulture, $"Exit: {GetCaller()}  {format}");
            DebugFormat(stackTrace, args);
        }

        /// <summary>
        ///     Logs a message object with the Info level.
        /// </summary>
        /// <param name="message">The message object to log.</param>
        public static void Info(object message)
        {
            Log.Info(message);
        }

        /// <summary>
        ///     Logs a message object with the INFO level including the stack trace of the System.Exception passed as a parameter.
        /// </summary>
        /// <param name="message">The message object to log.</param>
        /// <param name="exception">The exception to log, including its stack trace.</param>
        public static void Info(object message, Exception exception)
        {
            Log.Info(message, exception);
        }

        /// <summary>
        ///     Logs a formatted message string with the Info level.
        /// </summary>
        /// <param name="format">A String containing zero or more format items</param>
        /// <param name="args">An Object array containing zero or more objects to format</param>
        public static void InfoFormat(string format, params object[] args)
        {
            Log.InfoFormat(CultureInfo.InvariantCulture, format, args);
        }

        /// <summary>
        ///     Log a message object with the Warn level.
        /// </summary>
        /// <param name="message">The message object to log.</param>
        public static void Warn(object message)
        {
            Log.Warn(message);
        }

        /// <summary>
        ///     Log a message object with the Warn level including the stack trace of the System.Exception passed as a parameter.
        /// </summary>
        /// <param name="message">The message object to log.</param>
        /// <param name="exception">The exception to log, including its stack trace.</param>
        public static void Warn(object message, Exception exception)
        {
            Log.Warn(message, exception);
        }

        /// <summary>
        ///     Logs a formatted message string with the Warn level.
        /// </summary>
        /// <param name="format">A String containing zero or more format items</param>
        /// <param name="args">An Object array containing zero or more objects to format</param>
        public static void WarnFormat(string format, params object[] args)
        {
            Log.WarnFormat(CultureInfo.InvariantCulture, format, args);
        }

        private static string GetCaller()
        {
            var caller = string.Empty;
            try
            {
                var callingMethod = new StackFrame(2).GetMethod();
                var assembly = callingMethod?.Module.Assembly ?? Assembly.GetCallingAssembly();
                if (callingMethod?.DeclaringType != null)
                {
                    caller = string.Format(CultureInfo.InvariantCulture, $"{callingMethod.DeclaringType.Name}.{callingMethod.Name}");
                }
                else if (callingMethod?.Name != null)
                {
                    caller = callingMethod.Name.Length > assembly.GetName().Name.Length
                        ? callingMethod.Name.Substring(assembly.GetName().Name.Length + 1)
                        : callingMethod.Name;
                }
            }
            catch (Exception exp)
            {
                Log.Error(exp);
            }

            return caller;
        }
    }
}

