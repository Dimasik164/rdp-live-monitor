Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-RdpSessions {
    $rows = @()
    $raw = & query session 2>$null

    foreach ($line in ($raw | Select-Object -Skip 1)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $clean = ($line -replace '^\s*>', '').Trim()
        $parts = $clean -split '\s+'
        if ($parts.Count -lt 3) { continue }

        $session = $parts[0]
        $user = ''
        $id = ''
        $state = ''

        if ($parts[1] -match '^\d+$') {
            $id = $parts[1]
            if ($parts.Count -gt 2) { $state = $parts[2] }
        }
        else {
            $user = $parts[1]
            if ($parts.Count -gt 2) { $id = $parts[2] }
            if ($parts.Count -gt 3) { $state = $parts[3] }
        }

        if ($session -notlike 'rdp-tcp*') { continue }
        if ([string]::IsNullOrWhiteSpace($id) -or $id -eq '65536') { continue }

        $rows += [pscustomobject]@{
            User = $user
            Session = $session
            Id = $id
            State = $state
        }
    }

    return @($rows)
}

function Get-RdpConnections {
    return @(Get-NetTCPConnection -State Established -LocalPort 3389 -ErrorAction SilentlyContinue |
        Select-Object RemoteAddress, RemotePort, LocalAddress, LocalPort, OwningProcess |
        Sort-Object RemoteAddress, RemotePort)
}

function Get-RecentRdpEvents {
    $rows = @()

    $events = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 60 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in 21, 24, 25 }

    foreach ($e in $events) {
        $user = ''
        $sessionId = ''
        $address = ''

        try {
            $xml = [xml]$e.ToXml()
            $eventXml = $xml.Event.UserData.EventXML
            $user = [string]$eventXml.User
            $sessionId = [string]$eventXml.SessionID
            $address = [string]$eventXml.Address
        }
        catch { }

        $eventName = switch ($e.Id) {
            21 { 'Logon' }
            24 { 'Disconnect' }
            25 { 'Reconnect' }
            default { "Event $($e.Id)" }
        }

        $rows += [pscustomobject]@{
            Time = $e.TimeCreated.ToString('HH:mm:ss')
            Event = $eventName
            User = $user
            SessionId = $sessionId
            SourceIP = $address
        }
    }

    return @($rows)
}

function Clear-RdpHistory {
    $logs = @(
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    )

    foreach ($log in $logs) {
        wevtutil cl $log 2>$null
    }
}

function Test-ValidIp {
    param([string]$Ip)

    if ([string]::IsNullOrWhiteSpace($Ip)) { return $false }
    $parsed = $null
    return [System.Net.IPAddress]::TryParse($Ip.Trim(), [ref]$parsed)
}

function Test-ValidRemoteAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $value = $Address.Trim()

    if (Test-ValidIp $value) { return $true }

    if ($value -match '^(.+)/(\d{1,3})$') {
        $ip = $matches[1]
        $prefix = [int]$matches[2]
        if (-not (Test-ValidIp $ip)) { return $false }
        if ($ip -like '*:*') { return ($prefix -ge 0 -and $prefix -le 128) }
        return ($prefix -ge 0 -and $prefix -le 32)
    }

    if ($value -match '^(.+)-(.+)$') {
        return ((Test-ValidIp $matches[1].Trim()) -and (Test-ValidIp $matches[2].Trim()))
    }

    return $false
}

function Add-AddressToBlacklist {
    param([string]$Address)

    $addressClean = $Address.Trim()
    $ruleIn = "Blacklist_${addressClean}_IN"
    $ruleOut = "Blacklist_${addressClean}_OUT"

    if (-not (Get-NetFirewallRule -DisplayName $ruleIn -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleIn -Direction Inbound -Action Block -RemoteAddress $addressClean -Profile Any | Out-Null
    }
    if (-not (Get-NetFirewallRule -DisplayName $ruleOut -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleOut -Direction Outbound -Action Block -RemoteAddress $addressClean -Profile Any | Out-Null
    }
}

function Remove-AddressFromBlacklist {
    param([string]$Address)

    $addressClean = $Address.Trim()
    $removed = 0

    foreach ($name in @("Blacklist_${addressClean}_IN", "Blacklist_${addressClean}_OUT")) {
        $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if ($rule) {
            $rule | Remove-NetFirewallRule
            $removed++
        }
    }

    return $removed
}

function Get-BlacklistEntries {
    $rules = Get-NetFirewallRule -DisplayName 'Blacklist_*' -ErrorAction SilentlyContinue
    $addresses = @{}

    foreach ($r in $rules) {
        if ($r.DisplayName -match '^Blacklist_(.+)_(IN|OUT)$') {
            $address = $matches[1]
            $direction = $matches[2]
            if (-not $addresses.ContainsKey($address)) {
                $addresses[$address] = [ordered]@{
                    Address = $address
                    Inbound = 'No'
                    Outbound = 'No'
                }
            }

            if ($direction -eq 'IN') { $addresses[$address].Inbound = 'Yes' }
            if ($direction -eq 'OUT') { $addresses[$address].Outbound = 'Yes' }
        }
    }

    return @($addresses.Values | ForEach-Object { [pscustomobject]$_ } | Sort-Object Address)
}

function Get-BlacklistIps {
    $entries = Get-BlacklistEntries
    return @($entries | Select-Object -ExpandProperty Address)
}

function Get-SelectedListValue {
    param(
        [System.Windows.Forms.ListView]$List,
        [int]$Index = 0
    )

    if ($List.SelectedItems.Count -eq 0) { return '' }
    if ($List.SelectedItems[0].SubItems.Count -le $Index) { return '' }
    return $List.SelectedItems[0].SubItems[$Index].Text
}

function Fill-AddressFromList {
    param(
        [System.Windows.Forms.ListView]$List,
        [int]$Index = 0
    )

    $value = Get-SelectedListValue $List $Index
    if (-not [string]::IsNullOrWhiteSpace($value)) {
        $ipText.Text = $value
    }
}

function New-ListView {
    param(
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height,
        [string[]]$Columns
    )

    $view = New-Object System.Windows.Forms.ListView
    $view.Location = New-Object System.Drawing.Point($X, $Y)
    $view.Size = New-Object System.Drawing.Size($Width, $Height)
    $view.View = 'Details'
    $view.FullRowSelect = $true
    $view.GridLines = $true
    $view.HideSelection = $false
    $view.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $view.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#FFFFFF')
    $view.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#1F2937')

    foreach ($c in $Columns) {
        [void]$view.Columns.Add($c, 150)
    }

    return $view
}

function Set-ListRows {
    param(
        [System.Windows.Forms.ListView]$List,
        [object[]]$Rows,
        [string[]]$Props
    )

    $List.BeginUpdate()
    $List.Items.Clear()

    foreach ($row in $Rows) {
        $first = [string]$row.($Props[0])
        $item = New-Object System.Windows.Forms.ListViewItem($first)

        foreach ($p in ($Props | Select-Object -Skip 1)) {
            [void]$item.SubItems.Add([string]$row.$p)
        }

        [void]$List.Items.Add($item)
    }

    foreach ($col in $List.Columns) {
        $col.Width = -2
        if ($col.Width -lt 110) { $col.Width = 110 }
    }

    $List.EndUpdate()
}

function Fit-ListColumns {
    param([System.Windows.Forms.ListView]$List)

    if ($List.Columns.Count -eq 0) { return }

    foreach ($col in $List.Columns) {
        $col.Width = -2
        if ($col.Width -lt 110) { $col.Width = 110 }
    }

    $total = 0
    foreach ($col in $List.Columns) { $total += $col.Width }

    $available = $List.ClientSize.Width - 8
    if ($available -gt $total -and $List.Columns.Count -gt 0) {
        $extra = [Math]::Floor(($available - $total) / $List.Columns.Count)
        foreach ($col in $List.Columns) {
            $col.Width += $extra
        }
    }
}

function Style-Button {
    param(
        [System.Windows.Forms.Button]$Button,
        [string]$Back,
        [string]$Fore = '#FFFFFF'
    )

    $Button.FlatStyle = 'Flat'
    $Button.FlatAppearance.BorderSize = 0
    $Button.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Back)
    $Button.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Fore)
    $Button.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
    $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'RDP Live Monitor'
$form.Size = New-Object System.Drawing.Size(1040, 860)
$form.MinimumSize = New-Object System.Drawing.Size(900, 760)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#EEF3F9')
$form.Font = New-Object System.Drawing.Font('Segoe UI', 10)

$header = New-Object System.Windows.Forms.Panel
$header.Location = New-Object System.Drawing.Point(0, 0)
$header.Size = New-Object System.Drawing.Size(1040, 84)
$header.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#1D3557')
$header.Anchor = 'Top,Left,Right'
$form.Controls.Add($header)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'RDP Live Monitor'
$title.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 18)
$title.ForeColor = [System.Drawing.Color]::White
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(18, 12)
$header.Controls.Add($title)

$lastUpdate = New-Object System.Windows.Forms.Label
$lastUpdate.Text = 'Last refresh: -'
$lastUpdate.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$lastUpdate.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#DDEBFF')
$lastUpdate.AutoSize = $true
$lastUpdate.Location = New-Object System.Drawing.Point(22, 50)
$header.Controls.Add($lastUpdate)

$summary = New-Object System.Windows.Forms.TextBox
$summary.Location = New-Object System.Drawing.Point(20, 100)
$summary.Size = New-Object System.Drawing.Size(990, 74)
$summary.Anchor = 'Top,Left,Right'
$summary.Multiline = $true
$summary.ReadOnly = $true
$summary.ScrollBars = 'Vertical'
$summary.Font = New-Object System.Drawing.Font('Consolas', 11)
$summary.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#101828')
$summary.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#D1FADF')
$summary.Text = 'Loading current RDP sessions...'
$form.Controls.Add($summary)

$ipLabel = New-Object System.Windows.Forms.Label
$ipLabel.Text = 'IP / CIDR / range:'
$ipLabel.Location = New-Object System.Drawing.Point(20, 192)
$ipLabel.AutoSize = $true
$ipLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#334E68')
$form.Controls.Add($ipLabel)

$ipText = New-Object System.Windows.Forms.TextBox
$ipText.Location = New-Object System.Drawing.Point(145, 188)
$ipText.Size = New-Object System.Drawing.Size(245, 28)
$ipText.Font = New-Object System.Drawing.Font('Consolas', 10.5)
$form.Controls.Add($ipText)

$btnBlock = New-Object System.Windows.Forms.Button
$btnBlock.Text = 'Add Blacklist'
$btnBlock.Location = New-Object System.Drawing.Point(404, 186)
$btnBlock.Size = New-Object System.Drawing.Size(130, 32)
Style-Button $btnBlock '#D7263D'
$form.Controls.Add($btnBlock)

$btnUnblock = New-Object System.Windows.Forms.Button
$btnUnblock.Text = 'Remove IP'
$btnUnblock.Location = New-Object System.Drawing.Point(542, 186)
$btnUnblock.Size = New-Object System.Drawing.Size(120, 32)
Style-Button $btnUnblock '#2A9D8F'
$form.Controls.Add($btnUnblock)

$btnShow = New-Object System.Windows.Forms.Button
$btnShow.Text = 'Show List'
$btnShow.Location = New-Object System.Drawing.Point(670, 186)
$btnShow.Size = New-Object System.Drawing.Size(110, 32)
Style-Button $btnShow '#457B9D'
$form.Controls.Add($btnShow)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = 'Refresh'
$btnRefresh.Location = New-Object System.Drawing.Point(788, 186)
$btnRefresh.Size = New-Object System.Drawing.Size(110, 32)
Style-Button $btnRefresh '#FF9F1C' '#1F2937'
$form.Controls.Add($btnRefresh)

$btnClearHistory = New-Object System.Windows.Forms.Button
$btnClearHistory.Text = 'Clear History'
$btnClearHistory.Location = New-Object System.Drawing.Point(906, 186)
$btnClearHistory.Size = New-Object System.Drawing.Size(120, 32)
Style-Button $btnClearHistory '#6C757D'
$form.Controls.Add($btnClearHistory)

$labelSessions = New-Object System.Windows.Forms.Label
$labelSessions.Text = 'Current sessions'
$labelSessions.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11)
$labelSessions.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#1D3557')
$labelSessions.Location = New-Object System.Drawing.Point(20, 236)
$labelSessions.AutoSize = $true
$form.Controls.Add($labelSessions)

$sessionsView = New-ListView 20 262 990 130 @('User', 'Session', 'ID', 'State')
$sessionsView.Anchor = 'Top,Left,Right'
$form.Controls.Add($sessionsView)

$labelBlacklist = New-Object System.Windows.Forms.Label
$labelBlacklist.Text = 'Firewall blacklist'
$labelBlacklist.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11)
$labelBlacklist.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#1D3557')
$labelBlacklist.Location = New-Object System.Drawing.Point(20, 410)
$labelBlacklist.AutoSize = $true
$form.Controls.Add($labelBlacklist)

$blacklistView = New-ListView 20 436 990 94 @('Address / Pool', 'Inbound', 'Outbound')
$blacklistView.Anchor = 'Top,Left,Right'
$form.Controls.Add($blacklistView)

$labelConns = New-Object System.Windows.Forms.Label
$labelConns.Text = 'Active 3389 connections'
$labelConns.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11)
$labelConns.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#1D3557')
$labelConns.Location = New-Object System.Drawing.Point(20, 548)
$labelConns.AutoSize = $true
$form.Controls.Add($labelConns)

$connsView = New-ListView 20 574 990 88 @('RemoteAddress', 'RemotePort', 'LocalAddress', 'LocalPort', 'PID')
$connsView.Anchor = 'Top,Left,Right'
$form.Controls.Add($connsView)

$labelEvents = New-Object System.Windows.Forms.Label
$labelEvents.Text = 'Recent RDP events'
$labelEvents.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11)
$labelEvents.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#1D3557')
$labelEvents.Location = New-Object System.Drawing.Point(20, 680)
$labelEvents.AutoSize = $true
$form.Controls.Add($labelEvents)

$eventsView = New-ListView 20 706 990 84 @('Time', 'Event', 'User', 'SessionId', 'SourceIP')
$eventsView.Anchor = 'Top,Left,Right,Bottom'
$form.Controls.Add($eventsView)

$applyLayout = {
    $margin = 20
    $contentWidth = [Math]::Max(500, $form.ClientSize.Width - ($margin * 2))
    $header.Width = $form.ClientSize.Width
    $summary.Width = $contentWidth
    $sessionsView.Width = $contentWidth
    $blacklistView.Width = $contentWidth
    $connsView.Width = $contentWidth
    $eventsView.Width = $contentWidth

    $bottom = $form.ClientSize.Height - 22
    $eventsView.Height = [Math]::Max(84, $bottom - $eventsView.Top)

    Fit-ListColumns $sessionsView
    Fit-ListColumns $blacklistView
    Fit-ListColumns $connsView
    Fit-ListColumns $eventsView
}

$refreshAction = {
    try {
        $sessions = Get-RdpSessions
        $conns = Get-RdpConnections
        $events = Get-RecentRdpEvents
        $blacklist = Get-BlacklistEntries

        Set-ListRows $sessionsView $sessions @('User', 'Session', 'Id', 'State')
        Set-ListRows $blacklistView $blacklist @('Address', 'Inbound', 'Outbound')
        Set-ListRows $connsView $conns @('RemoteAddress', 'RemotePort', 'LocalAddress', 'LocalPort', 'OwningProcess')
        Set-ListRows $eventsView $events @('Time', 'Event', 'User', 'SessionId', 'SourceIP')
        & $applyLayout

        if ($sessions.Count -gt 0) {
            $summary.Lines = @($sessions | ForEach-Object { "ACTIVE: user=$($_.User) session=$($_.Session) id=$($_.Id) state=$($_.State)" })
        }
        else {
            $summary.Text = 'No current RDP sessions found by query session.'
        }

        $lastUpdate.Text = "Last refresh: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    }
    catch {
        $summary.Text = "Refresh error: $($_.Exception.Message)"
        $lastUpdate.Text = "Refresh failed: $((Get-Date).ToString('HH:mm:ss'))"
    }
}

$btnRefresh.Add_Click($refreshAction)

$btnBlock.Add_Click({
    $address = $ipText.Text.Trim()
    if (-not (Test-ValidRemoteAddress $address)) {
        [System.Windows.Forms.MessageBox]::Show('Enter an IP, CIDR subnet, or IP range.', 'Invalid address', 'OK', 'Warning') | Out-Null
        return
    }

    Add-AddressToBlacklist $address
    & $refreshAction
    [System.Windows.Forms.MessageBox]::Show("Added to blacklist: $address", 'Done', 'OK', 'Information') | Out-Null
})

$btnUnblock.Add_Click({
    $address = $ipText.Text.Trim()
    if (-not (Test-ValidRemoteAddress $address)) {
        [System.Windows.Forms.MessageBox]::Show('Enter an IP, CIDR subnet, or IP range.', 'Invalid address', 'OK', 'Warning') | Out-Null
        return
    }

    $removed = Remove-AddressFromBlacklist $address
    & $refreshAction
    [System.Windows.Forms.MessageBox]::Show("Removed rules: $removed", 'Done', 'OK', 'Information') | Out-Null
})

$btnShow.Add_Click({
    $ips = Get-BlacklistIps
    if ($ips.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Blacklist is empty.', 'Blacklist', 'OK', 'Information') | Out-Null
    }
    else {
        [System.Windows.Forms.MessageBox]::Show(($ips -join [Environment]::NewLine), 'Blacklisted IPs', 'OK', 'Information') | Out-Null
    }
})

$btnClearHistory.Add_Click({
    $answer = [System.Windows.Forms.MessageBox]::Show(
        'Clear local RDP event history? Firewall blacklist will not be changed.',
        'Clear RDP history',
        'YesNo',
        'Warning'
    )

    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    try {
        Clear-RdpHistory
        & $refreshAction
        [System.Windows.Forms.MessageBox]::Show('RDP history cleared.', 'Done', 'OK', 'Information') | Out-Null
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to clear history: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
})

$connsView.Add_Click({
    Fill-AddressFromList $connsView 0
})

$eventsView.Add_Click({
    Fill-AddressFromList $eventsView 4
})

$blacklistView.Add_Click({
    Fill-AddressFromList $blacklistView 0
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.Add_Tick($refreshAction)

$form.Add_Resize({
    & $applyLayout
})

$form.Add_Shown({
    & $applyLayout
    & $refreshAction
    $timer.Start()
})

[void]$form.ShowDialog()
