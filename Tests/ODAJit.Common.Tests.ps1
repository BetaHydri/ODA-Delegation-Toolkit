#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\ODAJit.Common.psm1') -Force

    function New-TestConfig ([hashtable]$Override = @{}) {
        $base = @{
            ForestName       = 'contoso.com'
            ForestRootServer = 'DC01.contoso.com'
            AccountGroupDN   = 'CN=ODA,OU=Groups,DC=child,DC=contoso,DC=com'
            Collector        = 'COL01.child.contoso.com'
            WorkingDirectory = 'C:\Assessments'
            WindowDay        = 'Sunday'
            WindowStart      = '02:00'
            ExecutorAccount  = 'CONTOSO\svc-ODA-JIT$'
        }
        foreach ($k in $Override.Keys) { $base[$k] = $Override[$k] }
        Test-ODAJitConfig -Config $base
    }

    function New-Task ([string]$Name, [string]$State = 'Ready', $LastRun = $null) {
        [pscustomobject]@{ TaskName = $Name; TaskPath = '\Test\'; State = $State; LastRunTime = $LastRun; LastTaskResult = 0 }
    }

    # 2026-10-04 is a Sunday
    $script:Window = Get-Date -Year 2026 -Month 10 -Day 4 -Hour 2 -Minute 0 -Second 0 -Millisecond 0
}

Describe 'Test-ODAJitConfig' {
    It 'applies defaults and parses window' {
        $c = New-TestConfig
        $c.GraceMinutes | Should -Be 30
        $c.WindowDay | Should -Be ([System.DayOfWeek]::Sunday)
        $c.WindowStartTime | Should -Be ([timespan]'02:00:00')
        $c.OdaTaskNames | Should -Be @('ADAssessment', 'ADSecurityAssessment')
    }
    It 'throws on missing required keys' {
        { Test-ODAJitConfig -Config @{ ForestName = 'x' } } | Should -Throw '*missing required key*'
    }
    It 'throws on invalid day' {
        { New-TestConfig @{ WindowDay = 'Sonntag' } } | Should -Throw '*WindowDay*'
    }
    It 'throws on invalid time format' {
        { New-TestConfig @{ WindowStart = '2 Uhr' } } | Should -Throw '*HH:mm*'
    }
    It 'throws if the PAM TTL does not outlive grant lead + deadline' {
        { New-TestConfig @{ TtlHours = 7; DeadlineHours = 6; GrantLeadMinutes = 60 } } | Should -Throw '*TtlHours*'
    }
    It 'skips the TTL check without PAM' {
        { New-TestConfig @{ TtlHours = 1; UsePamTtl = $false } } | Should -Not -Throw
    }
    It 'throws if the no-start timeout is not shorter than the deadline' {
        { New-TestConfig @{ NoStartTimeoutMinutes = 360; DeadlineHours = 6 } } | Should -Throw '*NoStartTimeoutMinutes*'
    }
    It 'requires a local working directory' {
        { New-TestConfig @{ WorkingDirectory = '\\srv\share' } } | Should -Throw '*WorkingDirectory*'
    }
    It 'loads the shipped example config' {
        { Import-ODAJitConfig -Path (Join-Path $PSScriptRoot '..\ODA-JIT.example.psd1') } | Should -Not -Throw
    }
}

Describe 'Get-ODAJitTriggerTimes' {
    It 'derives grant T-60 and watcher T+15 on the same day' {
        $t = Get-ODAJitTriggerTimes -Config (New-TestConfig)
        $t.GrantDay | Should -Be ([System.DayOfWeek]::Sunday)
        $t.GrantTime | Should -Be '01:00'
        $t.WatcherDay | Should -Be ([System.DayOfWeek]::Sunday)
        $t.WatcherTime | Should -Be '02:15'
    }
    It 'rolls the grant back to the previous day' {
        $t = Get-ODAJitTriggerTimes -Config (New-TestConfig @{ WindowDay = 'Monday'; WindowStart = '00:30' })
        $t.GrantDay | Should -Be ([System.DayOfWeek]::Sunday)
        $t.GrantTime | Should -Be '23:30'
    }
    It 'rolls the watcher forward across Saturday -> Sunday' {
        $t = Get-ODAJitTriggerTimes -Config (New-TestConfig @{ WindowDay = 'Saturday'; WindowStart = '23:50' })
        $t.WatcherDay | Should -Be ([System.DayOfWeek]::Sunday)
        $t.WatcherTime | Should -Be '00:05'
    }
}

Describe 'Get-ODAJitWindowStart' {
    BeforeAll { $script:cfg = New-TestConfig }
    It 'returns the upcoming window for the grant (T-60)' {
        Get-ODAJitWindowStart -Config $cfg -Reference $Window.AddMinutes(-60) | Should -Be $Window
    }
    It 'returns the current window for the watcher (T+15)' {
        Get-ODAJitWindowStart -Config $cfg -Reference $Window.AddMinutes(15) | Should -Be $Window
    }
    It 'returns the most recent window mid-week' {
        Get-ODAJitWindowStart -Config $cfg -Reference $Window.AddDays(3) | Should -Be $Window
    }
    It 'returns the upcoming window when the reference equals the window start' {
        Get-ODAJitWindowStart -Config $cfg -Reference $Window | Should -Be $Window
    }
}

Describe 'Get-ODARunState' {
    BeforeAll {
        $script:names = @('ADAssessment', 'ADSecurityAssessment')
        $script:common = @{ ExpectedTaskNames = $names; WindowStart = $Window; NoStartTimeoutMinutes = 90 }
    }
    It 'is Running while a task is running' {
        $tasks = @((New-Task 'ADAssessment' 'Running' $Window), (New-Task 'ADSecurityAssessment' 'Ready' $Window.AddDays(-7)))
        (Get-ODARunState -Tasks $tasks -Now $Window.AddMinutes(20) @common).Status | Should -Be 'Running'
    }
    It 'is Running while the assessment process exists even if tasks look idle' {
        $tasks = @((New-Task 'ADAssessment' 'Ready' $Window), (New-Task 'ADSecurityAssessment' 'Ready' $Window.AddMinutes(30)))
        (Get-ODARunState -Tasks $tasks -ProcessCount 1 -Now $Window.AddMinutes(90) @common).Status | Should -Be 'Running'
    }
    It 'treats Queued as running' {
        $tasks = @((New-Task 'ADAssessment' 'Queued' $Window.AddDays(-7)))
        (Get-ODARunState -Tasks $tasks -Now $Window.AddMinutes(5) @common).Status | Should -Be 'Running'
    }
    It 'is Finished when all tasks ran in the window and nothing runs' {
        $tasks = @((New-Task 'ADAssessment' 'Ready' $Window), (New-Task 'ADSecurityAssessment' 'Ready' $Window.AddMinutes(30)))
        $s = Get-ODARunState -Tasks $tasks -Now $Window.AddMinutes(120) @common
        $s.Status | Should -Be 'Finished'
        $s.RanTasks | Should -Be $names
    }
    It 'is Pending between the two assessments' {
        $tasks = @((New-Task 'ADAssessment' 'Ready' $Window), (New-Task 'ADSecurityAssessment' 'Ready' $Window.AddDays(-7)))
        $s = Get-ODARunState -Tasks $tasks -Now $Window.AddMinutes(25) @common
        $s.Status | Should -Be 'Pending'
        $s.MissingTasks | Should -Be @('ADSecurityAssessment')
    }
    It 'is Incomplete when a task has not started after the no-start timeout' {
        $tasks = @((New-Task 'ADAssessment' 'Ready' $Window), (New-Task 'ADSecurityAssessment' 'Disabled' $Window.AddDays(-7)))
        (Get-ODARunState -Tasks $tasks -Now $Window.AddMinutes(91) @common).Status | Should -Be 'Incomplete'
    }
    It 'reports configured tasks that do not exist on the collector' {
        $s = Get-ODARunState -Tasks @((New-Task 'ADAssessment' 'Ready' $Window)) -Now $Window.AddMinutes(10) @common
        $s.NotFound | Should -Be @('ADSecurityAssessment')
        $s.Status | Should -Be 'Pending'
    }
    It 'does not count a run from the previous week' {
        $tasks = @((New-Task 'ADAssessment' 'Ready' $Window.AddMinutes(-1)))
        $s = Get-ODARunState -Tasks $tasks -ExpectedTaskNames @('ADAssessment') -WindowStart $Window -NoStartTimeoutMinutes 90 -Now $Window.AddMinutes(10)
        $s.Status | Should -Be 'Pending'
    }
    It 'handles a never-run task (LastRunTime $null)' {
        $s = Get-ODARunState -Tasks @((New-Task 'ADAssessment' 'Ready' $null)) -ExpectedTaskNames @('ADAssessment') -WindowStart $Window -NoStartTimeoutMinutes 90 -Now $Window.AddMinutes(100)
        $s.Status | Should -Be 'Incomplete'
    }
}

Describe 'Wait-ODAJitCompletion (simulated clock)' {
    BeforeAll {
        $script:cfg = New-TestConfig @{ OdaTaskNames = @('ADAssessment') }

        # Runs the loop against a scripted timeline: $Timeline is a scriptblock(now) -> state | throw
        function Invoke-Simulation ([hashtable]$Config, [scriptblock]$Timeline) {
            $clock = @{ Now = $Window.AddMinutes($Config.WatcherStartOffsetMinutes); Sleeps = 0 }
            $getNow = { $clock.Now }.GetNewClosure()
            $sleep = { param($s) $clock.Now = $clock.Now.AddSeconds($s); $clock.Sleeps++ }.GetNewClosure()
            $getState = { & $Timeline $clock.Now }.GetNewClosure()
            $r = Wait-ODAJitCompletion -Config $Config -WindowStart $Window -GetCollectorState $getState -GetNow $getNow -Sleep $sleep 6>$null
            [pscustomobject]@{ Result = $r; End = $clock.Now; Sleeps = $clock.Sleeps }
        }
    }

    It 'revokes after run end + grace period' {
        # run 02:00 - 02:52
        $sim = Invoke-Simulation $cfg {
            param($now)
            if ($now -lt $Window.AddMinutes(52)) { @{ Tasks = @((New-Task 'ADAssessment' 'Running' $Window)); ProcessCount = 1 } }
            else { @{ Tasks = @((New-Task 'ADAssessment' 'Ready' $Window)); ProcessCount = 0 } }
        }
        $sim.Result.Outcome | Should -Be 'Finished'
        # first poll after 02:52 is 02:55 (5-min grid from 02:15) + 30 min grace
        $sim.End | Should -Be $Window.AddMinutes(85)
    }

    It 'keeps watching when a new run starts during the grace period' {
        # run 1: 02:00-02:40, run 2 (restart): 03:00-03:30
        $sim = Invoke-Simulation $cfg {
            param($now)
            if ($now -lt $Window.AddMinutes(40)) { @{ Tasks = @((New-Task 'ADAssessment' 'Running' $Window)); ProcessCount = 1 } }
            elseif ($now -lt $Window.AddMinutes(60)) { @{ Tasks = @((New-Task 'ADAssessment' 'Ready' $Window)); ProcessCount = 0 } }
            elseif ($now -lt $Window.AddMinutes(90)) { @{ Tasks = @((New-Task 'ADAssessment' 'Running' $Window.AddMinutes(60))); ProcessCount = 1 } }
            else { @{ Tasks = @((New-Task 'ADAssessment' 'Ready' $Window.AddMinutes(60))); ProcessCount = 0 } }
        }
        $sim.Result.Outcome | Should -Be 'Finished'
        $sim.End | Should -Be $Window.AddMinutes(120)
    }

    It 'returns Deadline if the run never ends' {
        $sim = Invoke-Simulation $cfg { param($now) @{ Tasks = @((New-Task 'ADAssessment' 'Running' $Window)); ProcessCount = 1 } }
        $sim.Result.Outcome | Should -Be 'Deadline'
        $sim.End | Should -Be $Window.AddHours($cfg.DeadlineHours)
    }

    It 'returns Deadline if the collector is unreachable' {
        $sim = Invoke-Simulation $cfg { param($now) throw 'RPC server unavailable' }
        $sim.Result.Outcome | Should -Be 'Deadline'
        $sim.Result.State | Should -BeNullOrEmpty
    }

    It 'returns Incomplete if the ODA task never starts' {
        $sim = Invoke-Simulation $cfg { param($now) @{ Tasks = @((New-Task 'ADAssessment' 'Ready' $Window.AddDays(-7))); ProcessCount = 0 } }
        $sim.Result.Outcome | Should -Be 'Incomplete'
        # no-start timeout 03:30 + 30 min grace
        $sim.End | Should -Be $Window.AddMinutes(120)
    }

    It 'shortens the grace period to the deadline' {
        $short = New-TestConfig @{ OdaTaskNames = @('ADAssessment'); DeadlineHours = 1; TtlHours = 3; NoStartTimeoutMinutes = 30; GraceMinutes = 30 }
        $sim = Invoke-Simulation $short {
            param($now)
            if ($now -lt $Window.AddMinutes(50)) { @{ Tasks = @((New-Task 'ADAssessment' 'Running' $Window)); ProcessCount = 1 } }
            else { @{ Tasks = @((New-Task 'ADAssessment' 'Ready' $Window)); ProcessCount = 0 } }
        }
        $sim.Result.Outcome | Should -Be 'Finished'
        $sim.End | Should -Be $Window.AddHours(1)
    }
}

Describe 'Helpers' {
    It 'parses PAM TTL member values' {
        $dn = 'CN=ODA,OU=Groups,DC=child,DC=contoso,DC=com'
        Get-ODAJitMemberTtl -MemberValues @("<TTL=3600>,$dn") -MemberDN $dn | Should -Be 3600
        Get-ODAJitMemberTtl -MemberValues @('CN=Other,DC=x', $dn) -MemberDN $dn | Should -Be 0
        Get-ODAJitMemberTtl -MemberValues @('CN=Other,DC=x') -MemberDN $dn | Should -BeNullOrEmpty
        Get-ODAJitMemberTtl -MemberValues @() -MemberDN $dn | Should -BeNullOrEmpty
    }
    It 'derives the DNS domain from a DN' {
        Get-ODAJitDomainFromDN 'CN=ODA,OU=Groups,DC=child,DC=contoso,DC=com' | Should -Be 'child.contoso.com'
        { Get-ODAJitDomainFromDN 'CN=ODA,OU=Groups' } | Should -Throw
    }
    It 'converts a local path to the admin share' {
        ConvertTo-ODAJitAdminSharePath -ComputerName 'COL01' -LocalPath 'c:\Assessments\' | Should -Be '\\COL01\C$\Assessments'
        ConvertTo-ODAJitAdminSharePath -ComputerName 'COL01' -LocalPath 'D:\' | Should -Be '\\COL01\D$'
    }
}
