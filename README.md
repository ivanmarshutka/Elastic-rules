# Elastic-rules </br>
Failed Login Attempts (Brute Force) </br>
event.action : "authentication_failure" </br> 
| stats count() by source.ip, user.name  </br>
| where count > 5</br>
Detects multiple failed login attempts from the same IP.</br>

Successful Logins from New Locations</br>
event.action : "authentication_success"  </br>
| stats count() by source.geo.country_iso_code, user.name  </br>
| where count == 1</br>
Flags first-time logins from new locations.</br>

Privilege Escalation</br>
event.action : "user_role_change" AND user.roles : "admin"</br>
Tracks accounts gaining admin roles.</br>

Multiple Account Lockouts</br>
event.action : "account_locked"  </br>
| stats count() by user.name  </br>
| where count > 3</br>
Identifies repeated account lockouts.</br>

Unusual Process Creation</br>
event.category : "process" AND process.name : ("powershell.exe" OR "cmd.exe") </br> 
| stats count() by host.name, process.command_line  </br>
| where count < 5</br>
Detects rare or suspicious process executions.</br>

Port Scanning</br>
network.transport : "tcp"  </br>
| stats unique_ports = cardinality(destination.port) by source.ip  </br>
| where unique_ports > 20</br>
Flags IPs scanning many ports.</br>

Outbound Traffic to Rare IPs</br>
network.direction : "outbound" </br> 
| stats count() by destination.ip  </br>
| where count < 3</br>
Monitors outbound connections to rare IPs.</br>

DNS Tunneling</br>
dns.question.name : /[a-zA-Z0-9]{50,}/</br>
Identifies abnormally long DNS queries.</br>

Data Exfiltration (Large Transfers)</br>
network.bytes > 10000000 AND network.direction : "outbound"</br>
Alerts on large outbound data transfers.</br>

File Integrity Monitoring (FIM)</br>
event.category : "file" AND event.action : ("modification" OR "deletion")</br>  
| stats count() by file.path  </br>
| where count > 10</br>
