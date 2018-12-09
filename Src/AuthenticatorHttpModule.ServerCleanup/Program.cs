namespace Authenticator.HttpModule.ServerCleanup
{
    using System;
    using System.Linq;
    using Microsoft.Web.Administration;
    using System.Windows.Forms;
    using System.Collections.Generic;
    using Authenticator.HttpModule.ServerCleanup.Properties;
    using System.Globalization;
    using log4net.Repository.Hierarchy;

    public class Program
    {
        #region constants
        private static readonly List<string> SelectedSitesToRestart = new List<string>();
        #endregion

        private static void Main()
        {
            //1.remove module : if exist
            RemoveModuleInterfaceFromServerSites(Resources.ServerName);

            //2. CleanConfiguration
            CleanConfiguration();

            //3. restart the server    
            Logger.Debug(Resources.RestartServerSite);
            RestartServerSites();
            Logger.Debug(Resources.ServerSitesRestarted);
        }

        /// <summary>
        /// Function to Remove the module app Directory & module interface from web.cofig
        /// </summary>
        /// <param name="servername"></param>
        internal static void RemoveModuleInterfaceFromServerSites(string servername)
        {
            try
            {
                //get all Sites of server which are not in selectedSite list and check if Module is present : remove it
                using (var serverManager = ServerManager.OpenRemote(servername))
                {
                    var isChanged = false;

                    //get all Sites of server which are not in selectedSite list and check if Module is present : remove it
                    if (serverManager == null)
                    {
                        var error = string.Format(CultureInfo.InvariantCulture, Resources.ServerUnavailable);
                        Logger.Error(error);
                    }

                    foreach (var site in serverManager.Sites)
                    {
                        if (site.Applications == null)
                        {
                            var error = string.Format(CultureInfo.InvariantCulture, Resources.NoApplicationPresent,site.Name);
                            Logger.Error(error);
                        }

                        #region interface remove
                        //select sites applications contain Modules
                        if (site.Applications != null)
                        {
                            try
                            {
                                var moduleApps =
                                    site.Applications.Where(x => x.Path.Contains(Resources.ModuleName)).ToList();
                                foreach (var app in moduleApps)
                                {
                                    site.Applications.Remove(app);
                                    isChanged = true;

                                    //Add site to restart server site list
                                    SelectedSitesToRestart.Add(site.Name);
                                    var error = string.Format(CultureInfo.InvariantCulture,Resources.RemovedApplication, site.Name);
                                    Logger.Debug(error);
                                }
                            }
                            catch (Exception exception)
                            {
                                var error = string.Format(CultureInfo.InvariantCulture,Resources.UnableToRemoveModuleInterface, site.Name,exception.Message);
                                Logger.Error(error);
                            }
                            #endregion
                        }
                    }
                    if (isChanged)
                    {
                        //commit changes in server
                        serverManager.CommitChanges();
                    }
                }
            }
            catch (Exception exception)
            {
                var error = string.Format(CultureInfo.InvariantCulture,Resources.ErrorUnableToRemoveInterface, exception.Message);
                Logger.Error(error);

                if (MessageBox.Show(Resources.ErrorPopupUnableToRemoveModuleApp, Resources.PopupMessageCaption, MessageBoxButtons.OK, MessageBoxIcon.Exclamation) == DialogResult.OK)
                {
                    System.Environment.Exit(0);
                }
            }
        }

        /// <summary>
        /// Function to clean up configuration
        /// </summary>
        private static void CleanConfiguration()
        {
            try
            {
                using (var serverManager = ServerManager.OpenRemote(Resources.ServerName))
                {
                    //get all Sites of server which are not in selectedSite list and check if Module is present : remove it
                    if (serverManager == null)
                    {
                        var error = Resources.ServerUnavailable;
                        Logger.Error(error);
                    }

                    #region removeconfigentry

                    foreach (var site in serverManager.Sites)
                    {
                        if (site.Applications == null)
                        {
                            var error = string.Format(CultureInfo.InvariantCulture, Resources.NoApplicationPresent,
                                site.Name);
                            Logger.Error(error);
                        }
                        try
                        {
                            foreach (var app in site.Applications)
                            {
                                var config = serverManager.GetWebConfiguration(site.Name, app.Path);
                                var modulesSection = config.GetSection(Resources.Modulesection);
                                var modulesCollection = modulesSection.GetCollection();

                                //select all the tags belong to the module elements "AuthenticationModule"
                                var moduleElements =
                                    modulesCollection.Select(
                                        module =>
                                            new
                                            {
                                                module,
                                                element = module.Attributes["name"].Value.Equals(Resources.Assemblyname)
                                            })
                                        .Where(t => t.element)
                                        .Select(t => t.module);

                                foreach (var module in moduleElements)
                                {
                                    module.Delete();
                                    serverManager.CommitChanges();

                                    var error = string.Format(CultureInfo.InvariantCulture,Resources.RemovedElementSuccess, site.Name);
                                    Logger.DebugFormat(error);
                                }
                            }
                        }
                        catch (Exception exception)
                        {
                            var error = string.Format(CultureInfo.InvariantCulture,Resources.ErrorUnableToRemoveModule, site.Name,
                                exception.Message);
                            Logger.ErrorFormat(error);
                        }
                        #endregion
                    }
                }
            }
            catch (Exception exception)
            {
                var error = string.Format(CultureInfo.InvariantCulture, Resources.ErrorUnableToRemoveModuleConfig, exception.Message);
                Logger.ErrorFormat(error);

                if (MessageBox.Show(Resources.ErrorPopupUnableToRemoveConfig, Resources.PopupMessageCaption, MessageBoxButtons.OK, MessageBoxIcon.Exclamation) == DialogResult.OK)
                {
                    System.Environment.Exit(0);
                }
            }
        }

        /// <summary>
        /// Function to restart the IIS Site
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        internal static void RestartServerSites()
        {
            try
            {
                using (var server = ServerManager.OpenRemote(Resources.ServerName))
                {
                    if (server == null)
                    {
                        Logger.Error(Resources.ServerUnavailable);
                        throw new HttpModuleException(Resources.ServerUnavailable);
                    }

                    if (server.Sites == null)
                    {
                        Logger.Error(Resources.NoServerSiteRegistered);
                        throw new HttpModuleException(Resources.NoServerSiteRegistered);
                    }
                    if ((SelectedSitesToRestart == null) || (SelectedSitesToRestart.Count == 0))
                    {
                        Logger.Info(Resources.NoServerSiteConfiguredWithfa);
                        return;
                    }

                    foreach (var serversite in SelectedSitesToRestart)
                    {
                        var site = server.Sites.FirstOrDefault(s => s.Name == serversite);

                        if (site != null)
                        {
                            //stop the site...
                            site.Stop();
                            if (site.State == ObjectState.Stopped)
                            {
                                Logger.Info(string.Format(CultureInfo.InvariantCulture, Resources.ServerSiteStopped,site.Name));
                            }

                            //restart the site...
                            site.Start();

                            if (site.State == ObjectState.Started)
                            {
                                Logger.Info(string.Format(CultureInfo.InvariantCulture, Resources.ServerSiteStarted,site.Name));
                            }
                        }
                        else
                        {
                            Logger.Error(string.Format(CultureInfo.InvariantCulture, Resources.ErrorRestartSite));
                            throw new HttpModuleException(string.Format(CultureInfo.InvariantCulture, Resources.ErrorRestartSite));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                var error = string.Format(CultureInfo.InvariantCulture, Resources.ErrorRestartServerSite, ex.Message);
                Logger.Error(error);
                throw new HttpModuleException(error);
            }
        }
    }
}
