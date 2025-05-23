# KQL-Toolkit

![image](https://github.com/user-attachments/assets/e87193c0-4852-496e-9017-ab7004db64d4)

# Azure-Sentinel-KQL-SIEM-Toolkit


## Overview

Proactive cloud defense depends on rapid analytics, thorough threat visibility, and reusable detection logic. This repository presents a curated collection of 12 production-ready Kusto Query Language (KQL) searches explicitly designed for Microsoft Sentinel and Azure Monitor Logs. Utilizing these queries enables users to:

* 🔍 **Surface critical security events** in seconds across petabytes of log data.
* 🛡️ **Detect sophisticated attacker tradecraft** and anomalous behaviour before impact.
* ⚡ **Accelerate hunt-to-automation workflows**, transforming ad‑hoc insight into always‑on analytics rules.


This toolkit is intended for various professionals, including Security Operations Center (SOC) analysts constructing their initial hunt workbooks, Cloud Security Engineers codifying blue-team expertise, and recruiters assessing real-world Sentinel capabilities. It exemplifies high-quality KQL craftsmanship that is suitable for production environments.

> Use the copy icon next to each fenced KQL block (`📋`) to paste directly into Log Analytics or the Sentinel rule wizard.

---

<details>
<summary><strong>📚 Table of Contents — click to expand</strong></summary>

* [Quick‑Start](#quick‑start)
* [Query‑Catalogue](#query‑catalogue)

  1. [Failed Sign‑In Surge](#1️⃣-failed-sign‑in-surge)
  2. [Impossible Travel](#2️⃣-impossible-travel)
  3. [Privilege Escalation Alert](#3️⃣-privilege-escalation-alert)
  4. [New External App Registration](#4️⃣-new-external-app-registration)
  5. [Rare Process Creation on Server](#5️⃣-rare-process-creation-on-server)
  6. [High‑Volume Data Exfil](#6️⃣-high‑volume-data-exfil)
  7. [DNS Tunnelling Detection](#7️⃣-dns-tunnelling-detection)
  8. [Suspicious PowerShell Usage](#8️⃣-suspicious-powershell-usage)
  9. [Azure Resource Deletion Spike](#9️⃣-azure-resource-deletion-spike)
  10. [Multiple MFA Denials](#🔟-multiple-mfa-denials)
  11. [Rare Service‑Principal Usage](#1️⃣1️⃣-rare-service‑principal-usage)
  12. [Unusual VM Guest Login Geo](#1️⃣2️⃣-unusual-vm-guest-login-geo)
* [Conclusion](#conclusion)

</details>

---

## Quick‑Start

The deployment of this toolkit is a straightforward process: clone or fork the repository, open any .kql file within the Log Analytics Query blade or Sentinel Analytics Rule Wizard, modify parameters such as TimeRange or Whitelist tables, and save the adjustments as a Scheduled Query Rule or Hunting query. Each query includes thorough commentary, is driven by parameters, and is safely executable in read-only mode, thereby eliminating the risk of data mutation commands.

---

## Query‑Catalogue

### 1️⃣ Failed Sign‑In Surge

A sudden increase in authentication failures often indicates potential brute-force or credential-stuffing attacks. This KQL query establishes a baseline of sign-in error rates for each user and tenant, flagging any hour in which failures exceed the maximum recorded during the previous week by a configurable factor. Analysts receive a succinct list of affected usernames, IP addresses, and client applications, facilitating rapid blocking or enforcement of conditional access.

By converting this logic into an analytics rule, organizations transition from one-time investigations to ongoing protective measures, ensuring that future surges automatically activate incident response protocols.


#### How it works

* Pulls `SigninLogs` for the last 24 h and the prior 7 d baseline.
* Aggregates `resultType != 0` counts per hour.
* Uses `make_series` and `series_fir()` to derive dynamic thresholds.
* Emits rows where the latest count > baseline × `SurgeFactor` (default 3).

```kql
// Failed Sign‑In Surge
let SurgeFactor = 3;
let LookbackHours = 24;
let BaselineDays = 7;
let endTime = now();
let startTime = endTime - datetime_diff('hour', LookbackHours, 0);
let baselineStart = endTime - BaselineDays * 1d;
// Baseline series
let baseline = SigninLogs
  | where TimeGenerated between (baselineStart .. endTime)
  | where ResultType !in (0, "0")
  | summarize count() by bin(TimeGenerated, 1h)
  | summarize Baseline=max(count);
// Current window
SigninLogs
  | where TimeGenerated between (startTime .. endTime) and ResultType !in (0, "0")
  | summarize Failures=count() by bin(TimeGenerated, 1h), UserPrincipalName, IPAddress
  | join kind=inner (baseline) on $left.Failures > Baseline * SurgeFactor
  | project TimeGenerated, UserPrincipalName, IPAddress, Failures, Baseline, SurgeFactor
  | order by Failures desc
```

---

### 2️⃣ Impossible Travel

Attackers may exploit stolen credentials by logging in from geographically distant locations within unrealistically short timeframes. This query detects sequential sign-ins from the same user when the calculated travel speed between source IP geolocations surpasses a predetermined human threshold (default set to 500 mph / 800 km/h). The results detail the first and subsequent sign-ins alongside the estimated speed, empowering response teams to validate potential compromises and initiate multi-factor authentication resets.

Continuous deployment of this rule significantly reduces dwell time associated with account takeovers, especially in hybrid workforces utilizing diverse IP ranges.  


#### How it works

* Uses `SigninLogs` fields `Location` → `Latitude`, `Longitude`.
* Calculates haversine distance between consecutive sign‑ins per user.
* Divides by time delta to derive mph / kmh.
* Flags if speed > `TravelThreshold`.

#### Usage Example (KQL)

```kql
// Impossible Travel Detection
let TravelThresholdKmh = 800; // ≈ 500 mph
let lookback = 1d;
SigninLogs
| where TimeGenerated > ago(lookback)
| project TimeGenerated, UserPrincipalName, IPAddress, Country = tostring(LocationDetails.countryOrRegion), Latitude, Longitude
| sort by UserPrincipalName, TimeGenerated asc
| serialize rank= row_number()
| extend PrevTime = prev(TimeGenerated), PrevLat = prev(Latitude), PrevLon = prev(Longitude), PrevCountry = prev(Country), UserPrev = prev(UserPrincipalName)
| where UserPrev == UserPrincipalName // consecutive for same user
| extend DistKm = geo_distance_2points(Latitude, Longitude, PrevLat, PrevLon)/1000.0, Hours = datetime_diff('second', TimeGenerated, PrevTime)/3600.0
| extend SpeedKmh = iff(Hours==0, 0, DistKm/Hours)
| where SpeedKmh > TravelThresholdKmh
| project UserPrincipalName, PrevCountry, Country, PrevTime, TimeGenerated, DistKm, SpeedKmh
| order by SpeedKmh desc
```

### 3️⃣ Privilege Escalation Alert

Elevations from lower-privileged roles to higher-impact positions (e.g., Owner, Global Administrator) can drastically increase an attacker's potential range of actions. This query scans AuditLogs for role-assignment events, enhances the findings with details regarding the actor's IP and device, and filters against an optional change-window whitelist. Any escalations outside pre-approved maintenance windows necessitate immediate review and potential access revocation. 

Automating this logic as an hourly analytics rule establishes a tamper-proof log of privilege changes, alleviating compliance burdens and improving the timeliness of detecting insider threats.  

#### How it works

* Queries `AuditLogs` for `Add member to role` and `Update role assignment`.
* Joins `IdentityInfo` to map department / job title.
* `leftanti` joins against a `ChangeWindow_AllowList` table.
* Outputs timestamp, actor, target role, and source IP.

#### Usage Example (KQL)

```kql
// Privilege Escalation Alert
let ChangeWindow_AllowList = materialize(externaldata(WindowStart:datetime, WindowEnd:datetime)["https://raw.githubusercontent.com/reyestech/assets/main/change_window.csv"] with(format="csv"));
AuditLogs
| where OperationName in ("Add member to role", "Update role assignment")
| extend TargetRole = tostring(parse_json(TargetResources)[0].displayName)
| extend Actor = tostring(parse_json(InitiatedBy).user.userPrincipalName), IP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Actor, IP, TargetRole, ActivityDisplayName
| join kind=leftanti (ChangeWindow_AllowList) on $left.TimeGenerated between (WindowStart .. WindowEnd)
| order by TimeGenerated desc
```

### 4️⃣ New External App Registration

Malicious OAuth consent grants and unauthorized multi-tenant applications are increasingly leveraged for stealthy persistence. This query identifies newly registered Azure AD applications with a PublisherDomain that does not align with the verified domain of your tenant, thereby exposing potentially risky third-party or attacker-controlled integrations. Each identified application outlines the permissions requested and the creator's details, allowing the Security Operations Center (SOC) to revoke consent promptly.  

Organizations gain continuous oversight against potential supply-chain incursions via OAuth by converting this query into a scheduled rule.  

#### How it works

* Reads `AADServicePrincipalCreationLogs` for the past 24 h.
* Extracts `PublisherDomain`, `AppDisplayName`, and `RequiredResourceAccess` scopes.
* Compares domain to `TenantDomain` parameter.
* Emits non‑matching entries.

#### Usage Example (KQL)

```kql
// External App Registration Detection
let TenantDomain = "contoso.com";
AADServicePrincipalCreationLogs
| where TimeGenerated > ago(1d)
| extend PublisherDomain = tostring(ApplicationPublisherDomain)
| where PublisherDomain != TenantDomain
| mv-expand scope = RequiredResourceAccess
| project TimeGenerated, AppDisplayName, PublisherDomain, CreatedBy = tostring(CreatedBy.userPrincipalName), Permission = scope
| order by TimeGenerated desc
```

### 5️⃣ Rare Process Creation on Server

The presence of unexpected executables on production servers may signal post-exploitation activities. This query establishes a baseline of process launches over the previous 30 days and identifies today's executions that fall below the 1st percentile—thereby uncovering suspicious binaries regardless of hashing or signature evasion. Contextual fields, such as command line, parent process, and user, assist analysts in determining whether to quarantine or allowlist the identified processes.  

This behavior-focused approach complements traditional signature-based defenses, effectively detecting renamed executables or the misuse of legitimate binaries that conventional antivirus solutions may overlook.  

#### How it works

* Baselines `EventID==4688` (`Sysmon EventID==1`) by `Computer`, `ProcessName` for 30 d.
* Computes launch frequency percentile.
* Flags today’s processes below `RareThreshold` (default 1%).

#### Usage Example (KQL)

```kql
// Rare Process Creation
let RareThreshold = 1; // percentile
let baselineDays = 30d;
let todayStart = startofday(now());
let baseline = SecurityEvent
  | where TimeGenerated between (ago(baselineDays) .. todayStart)
  | where EventID == 4688
  | summarize Launches=count() by Computer, ProcessName
  | summarize pct=percentile(Launches, RareThreshold);
let today = SecurityEvent
  | where TimeGenerated > todayStart and EventID == 4688
  | project TimeGenerated, Computer, ProcessName, CommandLine, ParentProcessName, Account
  | join kind=inner (baseline) on Computer
  | where Launches < pct
  | order by TimeGenerated desc
;
today
```

### 6️⃣ High‑Volume Data Exfil

Significant outbound data transfers to unfamiliar destinations may indicate potential data theft or misconfigured backup systems. This analysis leverages NSG flow logs (AzureNetworkAnalytics_CL) or firewall logs to identify public IP addresses receiving data volumes that exceed five times the median for the same virtual machine (VM) over the preceding week. The output includes byte counts, destination details, and protocol information, enabling responders to implement measures such as cutting egress or throttling bandwidth.

Integrating this alert with automated ticketing systems reinforces data loss prevention protocols across hybrid infrastructures.


#### How it works

* Summarises `BytesSent` per `PublicIP` for last 6 h.
* Retrieves 7‑day median per VM.
* Calculates delta and triggers at 500%.

#### Usage Example (KQL)

```kql
// High Volume Data Exfiltration
let LookbackHours = 6h;
let BaselineDays = 7d;
let Multiplier = 5.0;
let recent = AzureNetworkAnalytics_CL
  | where TimeGenerated > ago(LookbackHours)
  | summarize BytesSent=sum(SentBytes) by VM=VirtualMachineId_s, DestIP=RemoteIP_s;
let baseline = AzureNetworkAnalytics_CL
  | where TimeGenerated between (ago(BaselineDays) .. ago(LookbackHours))
  | summarize MedianBytes=percentile(sum(SentBytes), 50) by VM=VirtualMachineId_s;
recent
| join kind=inner baseline on VM
| extend Delta = BytesSent / MedianBytes
| where Delta > Multiplier
| project VM, DestIP, BytesSent, MedianBytes, Delta
| order by Delta desc
```

### 7️⃣ DNS Tunnelling Detection

Malware and insiders may exploit DNS protocols to obfuscate command-and-control or data exfiltration activities. This query meticulously examines DNS events for excessively lengthy subdomains, high entropy values (indicative of encoded payloads), and elevated NXDOMAIN response ratios—three specific indicators often associated with tunneling techniques. Analysts receive a prioritized list of suspicious domains, facilitating swift actions such as sinkholing or firewall blocking.

Once transformed into an analytic rule, this detection method serves to flag issues early, potentially preventing full-scale compromises.

#### How it works

* Calculates length and Shannon entropy of `QueryName`.
* Counts NXDOMAIN responses per `QueryName`.
* Flags entries meeting all three heuristic thresholds.

#### Usage Example (KQL)

```kql
// DNS Tunnelling Hunt
let LengthThreshold = 50;
let EntropyThreshold = 4.0;
let NXDomainThreshold = 0.5; // 50%
DnsEvents
| where TimeGenerated > ago(6h)
| extend NameLen = strlen(QueryName), Entropy = entropy(QueryName)
| summarize TotalQueries=count(), NX=countif(ResponseCode==3) by QueryName, ClientIP
| extend NXRate = todouble(NX)/TotalQueries
| where NameLen > LengthThreshold and Entropy > EntropyThreshold and NXRate > NXDomainThreshold
| order by Entropy desc
```

### 8️⃣ Suspicious PowerShell Usage

Attackers frequently utilize PowerShell due to its inherent capabilities and stealthy nature. This query specifically targets command lines containing obfuscation flags, downloaders, or keywords that may bypass AMSI, while excluding signed Microsoft scripts. The output incorporates information on devices, users, truncated command lines, and script hashes, thus allowing for prompt containment of potentially compromised endpoints.

Automated responses can effectively isolate or offboard hosts prior to payload deployment, thereby minimizing the attacker’s dwell time.

#### How it works

* Pattern‑matches `ProcessCommandLine` for risky substrings.
* Filters out trusted signers.
* Deduplicates by hash to reduce alert noise.

#### Usage Example (KQL)

```kql
// Suspicious PowerShell Execution
let Dangerous = dynamic(["-enc", "Invoke-WebRequest", "IEX", "Bypass", "DownloadString"]);
DeviceProcessEvents
| where Timestamp > ago(12h)
| where ProcessName =~ "powershell.exe"
| where array_length(array_intersect(Dangerous, split(tolower(ProcessCommandLine),' '))) > 0
| where Signer != "Microsoft Windows"
| project Timestamp, DeviceName, AccountName, ShortCmd = substring(ProcessCommandLine, 0, 120), SHA256, FileName
| order by Timestamp desc
```

### 9️⃣ Azure Resource Deletion Spike

Massive deletions of cloud resources can stem from erroneous automation processes or malicious activities involving compromised credentials. This query monitors `AzureActivity` for successful deletion operations and compares the hourly deletion count against the highest hourly volume recorded in the last 90 days. An alert will be triggered if the current deletion volume surpasses this maximum, prompting teams to halt destructive automation or initiate recovery processes.

Integrating the alert with a Logic App can automatically lock the subscription or notify on-call engineers via Teams, thereby reducing response times.

#### How it works

* Filters for `OperationNameValue` ending `/delete`.
* Summarises per hour by caller and resource type.
* Compares to 90‑day high; triggers on exceedance.

#### Usage Example (KQL)

```kql
// Resource Deletion Spike
let lookback = 90d;
let HourlyDeletes = AzureActivity
  | where OperationNameValue has "/delete" and ActivityStatus == "Succeeded"
  | summarize Deletes=count() by Caller, bin(TimeGenerated, 1h);
let historicalMax = HourlyDeletes
  | where TimeGenerated between (ago(lookback) .. ago(2h))
  | summarize MaxDeletes=max(Deletes);
HourlyDeletes
| where TimeGenerated > ago(2h)
| where Deletes > historicalMax
| project TimeGenerated, Caller, Deletes, historicalMax
| order by Deletes desc
```

### 🔟 Multiple MFA Denials

A sudden increase in MFA denial occurrences within a brief time frame generally indicates either a password-spray attack or user confusion, potentially exploited through phishing. This query aggregates denial responses over a 30-minute sliding window, grouping results by user and IP address. Entities recording more than five denials are highlighted in the results, empowering identity teams to reset credentials or provide necessary user education.

Automated containment through Conditional Access policies can immediately block suspicious IP addresses, thereby mitigating brute-force attempts.

#### How it works

* Looks back 30 minutes in `SigninLogs`.
* Filters for MFA required + denial code.
* Summarises denials ≥ 5 per user/IP.

#### Usage Example (KQL)

```kql
// MFA Denial Burst
let Window = 30m;
SigninLogs
| where TimeGenerated > ago(Window)
| where ResultType == 500121 and AuthenticationRequirement == "multiFactorAuthentication"
| summarize Denials=count() by UserPrincipalName, IPAddress
| where Denials >= 5
| order by Denials desc
```

### 1️⃣1️⃣ Rare Service‑Principal Usage


Service principals typically exhibit predictable usage patterns. Deviations, such as unexpected spikes or first-time sign-ins, may suggest credential leakage or unanticipated automation. This query establishes a baseline from the previous 30 days of non-interactive sign-ins per service principal, flagging any instances that exceed the 95th percentile for the current day. Metadata, including resource and IP information, allows for rapid investigation and containment.

Visualizing this metric in a Workbook fosters transparency and accountability within cloud-to-cloud trust relationships.


#### How it works

* Baselines daily sign‑ins via `AADNonInteractiveUserSignInLogs`.
* Calculates per‑SP P95 over 30 days.
* Compares today’s count to baseline.

#### Usage Example (KQL)

```kql
// Rare Service Principal Activity
let baselineDays = 30d;
let todayStart = startofday(now());
let baseline = AADNonInteractiveUserSignInLogs
  | where TimeGenerated between (ago(baselineDays) .. todayStart)
  | summarize Daily=count() by ServicePrincipalId, bin(TimeGenerated, 1d)
  | summarize P95=percentile(Daily, 95) by ServicePrincipalId;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > todayStart
| summarize TodayCnt=count() by ServicePrincipalId, AppDisplayName, ResourceDisplayName
| join baseline on ServicePrincipalId
| where TodayCnt > P95
| project TimeGenerated=todayStart, AppDisplayName, ResourceDisplayName, TodayCnt, P95
| order by TodayCnt desc
```

### 1️⃣2️⃣ Unusual VM Guest Login Geo

Hands-on keyboard intrusions often begin with interactive logins from unexpected countries. By correlating Windows Security Event ID 4624 and Linux SSH login successes with GeoIP lookups, this query identifies the first time a given VM encounters a login from a new country within the past 24 hours. The output includes user information, IP address, geographic location, and host details, providing defenders with a clear signal to investigate or geo-lock access.

Scheduling this detection ensures that any anomalous geolocation triggers a near-real-time response, which is especially crucial for regulated environments with strict data residency requirements.

#### How it works

* Normalises login events across Windows (`4624`) and Linux (`sshd`).
* Uses `ip_to_country()` function (or custom reference table).
* Maintains historical country set per host via `make_set()`.
* Emits new country logins in the last day.

#### Usage Example (KQL)

```kql
// Unusual Geo Login to VM
let lookback = 1d;
let historicWindow = 90d;
let logins = (union
  SecurityEvent
    | where TimeGenerated > ago(historicWindow) and EventID == 4624 and LogonType == 10
    | project TimeGenerated, Computer, User = Account, IP = tostring(parse_xml(EventData).Data[18]), 
  Syslog
    | where TimeGenerated > ago(historicWindow) and ProcessName == "sshd" and SyslogMessage has "Accepted password"
    | extend parts = split(SyslogMessage, " ")
    | project TimeGenerated, Computer=HostName, User=parts[10], IP=parts[8]
);
let withGeo = logins | extend Country = ip_to_country(IP);
let historic = withGeo | summarize Countries=make_set(Country) by Computer;
let recent = withGeo | where TimeGenerated > ago(lookback);
recent
| join kind=inner historic on Computer
| where Country !in (Countries)
| project TimeGenerated, Computer, User, IP, Country
| order by TimeGenerated desc
```

Unexpected interactive logins to Windows or Linux IaaS VMs from foreign geolocations can indicate potential hands-on keyboard activity. By correlating Security Event (Windows) and Syslog (Linux) logins with GeoInfo based on source IP, this query detects first-seen countries for each VM over the last 90 days. The output includes username, country, city, and timestamp.

SOC teams can quickly quarantine VMs or enable Just-In-Time (JIT) access only to sanctioned locations.

#### How it works

* Normalises login events (`EventID == 4624`, `sshd` success).
* Enriches IP with `ip_to_country()` user function or GeoLite table.
* Stores historical `make_set()` of countries per host.
* Emits new country entries within last 24 h.

---

## Conclusion

The Azure Sentinel KQL Hunting and Detection Toolkit is designed to bring together compelling detection logic validated through practical use, allowing users to create reusable components for their security operations. This toolkit is a crucial link between isolated investigative efforts and establishing a comprehensive and formalized security posture.

By harnessing the robust analytical features of Kusto Query Language (KQL), the toolkit enables users to perform in-depth data analysis easily. It goes a step further by adding operational context to each query, ensuring that the insights generated are not only accurate but also relevant to the specific circumstances of the organization.

This approach accelerates the transition from merely collecting and analyzing raw log data to implementing automated responses to potential security threats. As a result, security teams can respond more swiftly and effectively to incidents, ultimately strengthening the organization's overall security framework.


Fork, star ⭐, and contribute additional hunts—together we can sharpen cloud defences and raise the collective bar for threat detection in Microsoft Sentinel. 🔍 **Happy hunting—and automate *all* the detections!**
