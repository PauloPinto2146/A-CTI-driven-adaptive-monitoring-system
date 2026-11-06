# Test 9

This test is meant to test if giving the host's state after the sysmon configuration file is done can be used to add to the sysmon configuration file the host state. Because, until now, the host state is getting kinda ignored.
To this end, I did 5 runs of 2 scenarios:

- The "normal" version where I ask for everything first
- The "host" version where I do not give the host state at first and only give it after the sysmon configuration file production and ask to add them in a new config file

As per usual I will be answering some questions to determine the success of this test:
- Did the host version just add or modified the sysmon result?
- Does the host version take better account of the host's state than the "normal" version?
- Does the host version become too host focused?

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

(See KAG_test_9_total.md)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Before getting into the question I want to have a comparitive table of the runs:

| Host case | What did it add? | What did it take off? | What was different between the host and normal version? |
| --------- | ---------------- | --------------------- | ------------------------------------------------------- | 
| #1 | `OneDrive.exe` for **T1567**; `wsl.exe` for **T1572**; `python.exe` for **T1071.001**  | Specific RDP port **3389** | The normal version did not add none of the things added, but seemed to have a better noise reduction by addding port filtering
| #2 | `OpenConsole.exe` for **T1190**, `wsl.exe` for **T1572** | **Nothing**, just added extra | The host version added the `FortiClientEMX.exe` image (eventhought it knows it is not on the host state, which I find to be interesting), the `OpenConsole.exe` and `wsl.exe` image. The host version omited the `certutil.exe` and the `rundll32.exe` images (which rundll32.exe was part of the security analysis and was taken off without explanation)
| #3 | `python.exe` for **T1190** and `wsl.exe` for **T1572** | Image `w3wp.exe` because "was not found in the running processes list" |  Host-after version considered that port 3389 should only be monitored with a limited image set; it removed the `w3wp.exe` image as mentioned before; it added the `wsl.exe` image
| #4 | "Added python.exe to T1071.001 and T1041 rules because it is installed and currently running on the host, representing a significant vector for C2 and data exfiltration." | "Removed w3wp.exe from T1190 rules as it is not present in the running processes, but kept shell monitoring since port 80/443 are listening." |  "Normal" version excluded `firefox.exe` specifically as one of the possible ways of C2 exfiltration (which does not make sense since Exfiltration over web services was one of the reported attack patterns) while the Host version added `python.exe` for T1567;
| #5 | "  - Added: 'python.exe' (Confirmed installed and running; critical for C2/Exfil monitoring). - Added: 'docker.exe', 'com.docker.backend.exe' (Confirmed installed; relevant for T1190 container exploitation). - Added: 'wsl.exe' (Confirmed installed/running; relevant for both T1190 and T1572)." | "Removed: 'w3wp.exe' (Not found in running processes or installed services)." | The host version has `docker.exe`, `com.docker.backend.exe`, `python.exe`, `wsl.exe` added 

# Questions answered

- Did the host version just add or modified the sysmon result?
A.: Compared to the "before" version it sometimes just added (like #2) but most of the times it removed some images because were not currently running in the host's state.

- Does the host version take better account of the host's state than the "normal" version?
A.: I would say yes, some "normal" versions did have the host's state taken into account but most of them were just not all included as the "host-after" version

- Does the host version become too host focused? 
A.: The removal of `w3wp.exe` could be considered a "too focused" method of applying the moniroting rules. Some of the times it did considered keeping some rules eventhough it were not written in the host's state, for examples: 
	- "Even though port 3389 is not currently listening, the security analysis requires monitoring for outbound RDP attempts (Lateral Movement)."
	- Retained FortiClientEMS.exe monitor despite not being in the current process list to protect the server against the identified CVE-2023-48788."