@{
    # ODA-JIT configuration - ONE file per AD forest (e.g. ODAJit.contoso.psd1).
    # Used by Start-ODAJitGrant.ps1, Start-ODAJitRevokeWatcher.ps1 and Register-ODAJitTasks.ps1.

    # --- Forest / accounts -------------------------------------------------------------
    ForestName         = 'contoso.com'                     # label for task, log and event names
    ForestRootServer   = 'DC01.contoso.com'                # writable DC of the forest ROOT domain
    # Permanent group that contains the ODA gMSA (AD + AD Security); this group is toggled in EA
    AccountGroupDN     = 'CN=ODA-Assessment-Accounts,OU=Groups,DC=child1,DC=contoso,DC=com'
    # Global Catalogs in the collector's AD site (used by the gMSA's KDC to expand universal groups)
    SiteGlobalCatalogs = @('DC01.child1.contoso.com')
    # Automation gMSA that runs the grant/revoke tasks on the Tier-0 host
    ExecutorAccount    = 'CONTOSO\svc-ODA-JIT$'

    # --- Collector / ODA ------------------------------------------------------------------
    Collector          = 'ODA-COL-CONTOSO.child1.contoso.com'   # FQDN of the on-prem server (not the Azure Arc resource name)
    WorkingDirectory   = 'C:\Assessments'                  # ODA WorkingDirectory on the collector
    OdaTaskNames       = @('ADAssessment', 'ADSecurityAssessment')
    OdaProcessNames    = @('OMSAssessment.exe')

    # --- Weekly window (must match the ODA task schedule on the collector) ----------------
    WindowDay          = 'Sunday'                          # English DayOfWeek name
    WindowStart        = '02:00'                           # HH:mm, start of the FIRST ODA task

    # --- Timing ---------------------------------------------------------------------------
    GrantLeadMinutes          = 60   # grant this long before WindowStart
    WatcherStartOffsetMinutes = 15   # watcher starts this long after WindowStart
    PollMinutes               = 5    # watcher polling interval
    GraceMinutes              = 30   # wait after the end signal before revoking
    NoStartTimeoutMinutes     = 90   # tasks not started by then count as 'not run' (> last task offset)
    DeadlineHours             = 6    # hard revoke at WindowStart + DeadlineHours (>= 3x longest run)
    TtlHours                  = 8    # PAM TTL backstop; must exceed GrantLead + Deadline
    UsePamTtl                 = $true  # $false if the PAM optional feature is not enabled (FFL < 2016)
    VerifyTimeoutMinutes      = 30   # max wait for the membership to show up on SiteGlobalCatalogs

    # --- Logging --------------------------------------------------------------------------
    LogDirectory       = 'C:\ODA-JIT\Logs'
}
