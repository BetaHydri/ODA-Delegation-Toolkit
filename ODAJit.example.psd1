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
    WorkingDirectory   = 'C:\Assessments'                  # folder with the *Assessment subfolders (ODA-version dependent, e.g. C:\MicrosoftAssessments\Collect)
    # Prerequisite: the ODA tasks (OdaTaskNames) must already exist on the collector - ODA-JIT only starts
    # and watches them. New FullEA instance: create them first with Add-ADAssessmentTask /
    # Add-ADSecurityAssessmentTask (see docs\ODA-JIT-Deployment.md, step 5), then fill in OdaTaskPath.
    OdaTaskNames       = @('ADAssessment', 'ADSecurityAssessment')  # only assessments needing Enterprise Admins (NOT WindowsServerAssessment)
    # Optional: restrict to ONE ODA instance (workspace) when several run on the collector, e.g. the old
    # delegation tasks next to the FullEA tasks. Folder prefix of the tasks (see Get-ScheduledTask).
    # OdaTaskPath     = '\Microsoft\Operations Management Suite\AOI-<WorkspaceId-of-FullEA-LAW>\'
    OdaProcessNames    = @('OMSAssessment.exe')

    # --- Weekly window (must match the ODA task schedule on the collector) ----------------
    WindowDay          = 'Sunday'                          # English DayOfWeek name
    WindowStart        = '02:00'                           # HH:mm, start of the FIRST ODA task

    # --- Timing ---------------------------------------------------------------------------
    # Timeline: Grant (WindowStart - GrantLead) -> WindowStart -> Watcher (+offset) -> end signal + Grace -> revoke
    #           NoStartTimeout / Deadline (both from WindowStart) end the wait early / at the latest;
    #           the PAM TTL (from the grant) removes EA by itself if the watcher or host fails.
    GrantLeadMinutes          = 60   # grant this long before WindowStart (replication + ticket refresh time)
    WatcherStartOffsetMinutes = 15   # watcher starts this long after WindowStart
    PollMinutes               = 5    # watcher polling interval
    GraceMinutes              = 30   # wait after the end signal (all tasks ran, no OMSAssessment.exe), then re-check, then revoke
    NoStartTimeoutMinutes     = 90   # from WindowStart: a task not started by then counts as 'not run' -> revoke early (> last task offset, < Deadline)
    DeadlineHours             = 6    # from WindowStart: hard revoke regardless of state (>= 3x longest run)
    TtlHours                  = 8    # from the grant: PAM TTL backstop; must exceed GrantLead + Deadline (keep ~1 h reserve)
    UsePamTtl                 = $true  # $false if the PAM optional feature is not enabled (FFL < 2016)
    VerifyTimeoutMinutes      = 30   # max wait for the membership to show up on SiteGlobalCatalogs

    # --- Logging --------------------------------------------------------------------------
    LogDirectory       = 'C:\ODA-JIT\Logs'
}
