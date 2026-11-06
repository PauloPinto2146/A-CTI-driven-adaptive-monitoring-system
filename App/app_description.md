# CTI / Security application

This section of the project stores a simple web service that is meant to trigger sysmon events.

In the first attempt I used "Owasp juice shop", a web application fit for web attack testing that I thought to be sufficient for the porpuses of this dissertation.
But, when gathering traffic and logs in my stress testing with apache jmeter, I noticed that the sysmon's CPU usage would not go up with the increasing amount of threads requesting the web server. Analysing the number of logs also did not have a significant increase.

In that matter, I thought to be better to develop myself a simple web service that would trigger sysmon events.

This file describes the possible action of this simple web service and what is the meant impact and utility.


First and foremost, there are sysmon events that are simply not common to trigger in web services. They are meant to catch attack behavior and/or sysmon service events. So, the first thing to do is exclude those sysmon events:

- **2 (File Creation Time)** could be used in a "backup" request maybe. But I think is a bit forced.
- **4 (Sysmon State Change)** is not even "loggable".
- **6 (DriverLoad)** would need to load drivers into the kernel. There is no functional way to use this in a web service.
- **8 and 25** are CreateRemoteThread and ProcessTampering respectively. They are meant to discover process injection attacks, not typical of legitimate web services.
- **9 (RawAccessRead)** does direct read on the disk (C:). Wouldn't be normal in a web service to trigger this event.
- **12/13/14 (Registry events)** are not common to trigger in a web service every-day use. 
- **16 (Sysmon configuration change)** is only meant to log when sysmon service has a new configuration of the host (in this case, the server). 
- **19/20/21 WmiEvent (filter/consumer/consumer filter)** are meant to catch host discovery attack patterns.
- **24 (ClipboardChange)** does not make sense to trigger in the host of a web service.
- **23/27/28 (FileDeleteArchived/FileBlockExecutable / FileBlockShredding)** are meant to be a configurable event that blocks files .exe to be genertaed and files from being deleted respectively


So now, we have:

- 1 Process Create
- ~~2 File creation time~~
- 3 Network connection detected
- ~~4	Sysmon service state change (cannot be filtered)~~
- 5 Process terminated
- ~~6 Driver Loaded~~
- 7 Image loaded
- ~~8	CreateRemoteThread detected~~
- ~~9 RawAccessRead detected~~
- 10 Process accessed
- 11 File created
- ~~12 Registry object added or deleted~~
- ~~13 Registry value set~~
- ~~14 Registry object renamed~~
- 15 File stream created
- ~~16 Sysmon configuration change (cannot be filtered)~~
- 17 Named pipe created
- 18 Named pipe connected
- ~~19 WMI filter~~
- ~~20 WMI consumer~~
- ~~21 WMI consumer filter~~
- 22 DNS query
- ~~23 File Delete archived~~
- ~~24 New content in the clipboard~~
- ~~25 Process image change~~
- 26 File Delete logged
- ~~27 File Block Executable~~
- ~~28 File Block Shredding~~
- 29 File Executable Detected

With those out of the way, next I showcase the description of the application, the action that can be taken from the client and the sysmon events that each request triggers.


### Web service description and motivation
Since this dissertation tackles Cyber Threat Intelligence and this application needs to manipulate file generation and deletion I thought that a CTI storage application would be a good web service idea.
The main purpose of this web service is to be a threat report storage and be used in a trusted enviroment that does not need to access control. It can both store, add information and delete CTI reports, as well as having some extra cyber security actions to add some extra diversity and sysmon event triggering.

### Actions
With this description in mind the actions that can be taken are defined as:

- Create a threat report description file. This will spawn a new process that creates a file with the desired content and title. **Triggers events 1, 5 and 11** 
- Adding IP address meta data with file streams. For example, a "APT23_description.txt" file can be added a "ip_addrs.txt" file that stores structured IP addresses associated with that threat report. **Triggers events 15**
- Getting additional information of IP addresses which will have the following sequence of events:
	- A main process will be created (**triggers event 1**)
	- The main process will spawn as many child processes as IP addresses in the stream file (**triggers event 1**)
	- Each child process will request the ip-api for information (**triggers event 3 and 22**) 
	- The main process will periodically check on the child processes (**triggers event 10**) and check if ended (**triggers event 5**)
- Read threat reports. Which can be implemented with pipes to **trigger events 17 and 18**
- Upload files and generate hashes. This request will have a rather unique design "drop-run-delete" but it will be for sysmon event spawning purposes.
	- A process will create a unique clamAV_temp directory for a user
	- Then copy the necessary clamAV files into the temporary directory (**which will trigger the events 1, 5, 7, 11 29**)
	- Run the sigtool 
	- Clean the directory (**which will trigger event 26**)
- Clean the directory. Which eliminates the users' files (**triggers event 26**)


# Scenario - Think times

### Action 1
Action 1 (create the threat reports) will be implemented having a random number of random characters of the threat description. Based on the 5 case scenarios that I have. Each one having a description with:

- 117 words / 882 characters (event 3342)
- 124 words / 932 characters (event 3418)
- 113 words / 871 characters (event 3945)
- 109 words / 910 characters (event 3967)
- 128 words / 1024 characters (event 8750)

In apache jmeter each thread will periodically, having this words in mind and assuming that a threat reporter is an office worker (see table 2), request with a minimum and a maximum value of time to write a threat report, being:

$$ Max_{typing time} = \frac{117 + 124 + 113 + 109 + 128}{5} * \frac{1}{50} = \frac{118.2}{50} = 2.364 minutes \approx 142 seconds$$
$$ Min_{typing time} = \frac{117 + 124 + 113 + 109 + 128}{5} * \frac{1}{50} = \frac{118.2}{60} = 1.97 minutes \approx 118 seconds$$

So, the apache jmeter implementation of this request will have a uniform random timer between 118 annd 142 seconds and a random number of characters between 871 and 1024.

### Action 2
Action 2 (attach ip addresses) allows an user to create a stream in a report file with an ip-address.

The think time of this one will be equivalent of filling a short form, 5 to 15 seconds (see table 1) and each IP address will be formatted like:

```
${__Random(1,255)}.${__Random(1,255)}.${__Random(1,255)}.${__Random(1,255)}
```

To minimize error chances, there will be a setup thread that creates a pre-defined number of threat reports so this action, 3, 4 and 5, can always have some file to work with.

### Action 3
Action 3 (check ip addresses). This action gives a simluated random geolocation of all IP addresses that are in a stream of a file.

The think time of this will be a union of:
- Browing a list/catalog, simulating the browse of a file action (5-15 seconds)
- Reading a product description (10-30 seconds), in this case the geolocation of the IP addresses.


### Action 4
Action 4 (read file). This action will have a similar to the action 3. In this case joining:

- Browing a list/catalog, simulating the browse of a file action (5-15 seconds)
- Reading a product description (30-90 seconds), in this case the descriptions being the triple time of reading the geolocation of IP addresses.

### Action 5
Action 5 (getting hash of a file). This action will have a similar to the action 3. In this case joining:

- Browing a list/catalog, simulating the browse of a file action (5-15 seconds)
- Reading a product description (5-15 seconds), in this case the hash of the file which is 1/2 of the time to read the geolocation of the IP addresses.

### Action 6
Action 6 (deleting all user's files), can be simulated like a button to delete:

- Between search results and clicking one (3-10s)

#### Table 1

| User Action 								| Typical Think Time 	| Range 		 |
| ----------------------------------------- | --------------------- | -------------- |
| Reading a product description				| 10-30 seconds			| 5-60 seconds	 |
| Filling a short form (login)				| 5-15 seconds			| 3-30 seconds	 |
| Filling a long form (checkout)			| 30-90 seconds			| 15-180 seconds |
| Browsing a list/catalog					| 5-15 seconds			| 2-30 seconds	 |
| Deciding on a purchase					| 15-60 seconds			| 5-120 seconds	 |
| Between search results and clicking one	| 3-10 seconds			| 1-15 seconds	 |

Based on https://www.testerrank.com/paths/performance/key-metrics/think-time-and-pacing

#### Table 2

| User Type					| Average WPM	| Notes 										|
| ------------------------- | ------------- | --------------------------------------------- |
| General population		| ~40 WPM		| Hunt-and-peck typing, untrained 				|
| Touch typist (average)	| ~52 WPM		| Dhakal et al., 2018 (37,000 participants) 	|
| Office worker				| 50–60 WPM		| Daily keyboard use, mixed technique 			|
| Professional writer		| 60–80 WPM		| Journalists, content creators, authors		|
| Transcriptionist			| 75–100 WPM	| Professional requirement, trained technique	|
| Competitive typist		| 120–150+ WPM	| Speed typing competitions, top percentile		|

Based on https://mindbenchmark.com/typing-test/average-wpm

# Scenarios - Proportions

https://dl.acm.org/doi/pdf/10.1145/2398776.2398827
This paper studies how dropbox data flows are composed in 4 scenarios: 2 *Homes* and 2 *Campus*, i.e., *Home 1 and Home 2 consist of ADSL and Fiber to the Home (FTTH) customers of a nation-wide ISP* and Campus are *instead collected in academic environments: Campus 1 mostly monitors wired workstations in research and administrative offices of the Computer Science Department in a European university. Campus 2 accounts for all traffic at the border routers of a second university, including campus-wide wireless access points and student houses*.

Knowing these 4 scenarios, I will be basing my scenario on Home 1 and 2 results which because they have the most data exposed in the paper.

The study says that:
- *Dropbox users tend to download more than upload. \[...\] Overall, the total downloaded data in Campus 2 is 2.4 times higher than the total uploaded datas.*

- *The occasional group represents around 30% of the totalIP addresses*. 
- *The upload-only group accounts for around 7% of the IP addresses, and is responsible for a significant amount of uploads (21% in Home 1 and 11% in Home 2 )*. 
- *\[...\] the download-only group. This group is, however, very significant in both number of IP addresses (26% in Home 1 and 28% in Home 2 ) and transferred volume (25% and 28%, re-spectively)*
- *the heavy group is responsible for most of the volume transferred by Dropbox clients. \[...\] and are responsible for more than 50% of the Dropbox sessions.*

In the web application there are 2 well-definde types of actions:
- Writing actions: Action 1 (create report), Action 2 (write IP addresses), Action 6 (Delete files)
- Reading actions: Action 3 (Check IPs), Action 4 (read report), Action 5 (read file hash)

Having this established, there will be 2 types of uses in the test scenario:

- "Download-only" (27%): threads that only execute reading actions (3, 4, 5)
- "Upload-only" (7%): threads that only execute writing actions (1, 2, 6)
- "Heavy" (35%): threads that execute both
- "Occasional" (31%) - negligible

Ignoring the occasional users, we have the following proportions:

- "Download-only" $ = \frac{27 * 100}{100 - 31} \approx 39\% $
- "Upload-only" $ = \frac{7 * 100}{100 - 31} \approx 10\% $
- "Heavy" $ = \frac{35 * 100}{100 - 31} \approx 51\% $

After testing with apache jmeter some scenarios I ended up with counting on 4 levels of activity scenarios:

- Low: 60 requests / min (1 per second)
- Medium:  240 request / min (4 per second)
- High: 600 requests / min (10 per second)

While monitoring "All" with sysmon the Low scenario was slightly impactful, Medium being a noticeble change and high triggering a slow state of the server in question. Overload is just 

Between the 3 actions of each type of user I will be using 3 profiles:

- Most frequent (65%)
- Occasional (30%)
- Rare (5%)

Which can be mapped to:

### Upload-only users:
- Action 2 - Most frequent (65%), since this actions can only attach one IP address at a time and making it more common than creating a file or deleting the directoy
- Action 1 - Occasional (30%), since threats are a relatively occasional event. Nonetheless, since this web service is supposed to serve the purpose of a CTI storage, so it is farely frequent.
- Action 6 - Rare (5%), since this action is destructive and not desired many times.

### Download-only users:
- Action 3 - Most frequent (65%), since knowing the IP addresses and their location is useful information for SOC's and can be more requested than other read operations.
- Action 4 - Occasional (30%), since reading a whole report would be in reviewing it, and is not a repetitive action
- Action 5 - Rare (5%), since this action is specialized and ponctual.

### Heavy users:
- Action 2 and 3 - Most frequent (32.5%)
- Action 1 and 4 - Occasional (15%)
- Action 5 and 6 - Rare (2.5%) 
(Evenly distribution of actions)

That said, for each action:

| User Action 								| Racionale 																| Proportion 	 | Avg. time |
| ----------------------------------------- | ------------------------------------------------------------------------- | -------------- | --------- |
| Action 1 (create report)					| 51% of users x 15% (occasional) + 10% of users x 30% (occasional)			| 10.65%		 | 130s 	 |
| Action 2 (attach ip addresses)			| 51% of users x 32.5% (Most frequent) + 10% of users x 65% (Most frequent) | 23.075%		 | 10s 		 |
| Action 3 (check IP addresses)				| 51% of users x 32.5% (Most frequent) + 39% of users x 65% (Most frequent	| 41.925%		 | 30s 		 |
| Action 4 (read report)					| 51% of users x 15% (occasional) + 39% of users x 30% (occasional)			| 19.35%		 | 70s 		 |
| Action 5 (Get file's hash)				| 51% of users x 2.5% (rare) + 39% of users x 5% (rare)						| 3.225%		 | 20s 		 |
| Action 6 (delete directory)				| 51% of users x 2.5% (rare) + 10% of users x 5% (rare)						| 1.775%		 | 6.5s 	 |

Besides think time, I also measured the process time in the low scenario so to have a base of which can be seen as a normal and unaffected process time. Getting the results:

| User Action 					 | Avg. time | Process time | Total time (T) |
| ------------------------------ | --------- | ------------ | -------------- |
| Action 1 (create report)		 | 130s 	 | 0.5s 		| 130.5s		 |
| Action 2 (attach ip addresses) | 10s 		 | 0.01s 		| 10.1s		     |
| Action 3 (check IP addresses)	 | 30s 		 | 0.16s 		| 30.2s		     |
| Action 4 (read report)		 | 70s 		 | 0.13s 		| 70.1s 		 |
| Action 5 (Get file's hash)	 | 20s 		 | 3.33s 		| 23.33s	     |
| Action 6 (delete directory)	 | 6.5s 	 | 0.02s 		| 6.5s		     |

Knowing these proportions, now we use the proportions to implement a Precise Throughput Timer (PTT) (https://jmeter.apache.org/usermanual/component_reference.html#Precise_Throughput_Timer):

```
 Precise Throughput Timer

This timer introduces variable pauses, calculated to keep the total throughput (e.g. in terms of samples per minute) as close as possible to a given figure. The timer does not generate threads, so the resulting throughput will be lower if the server is not capable of handling it, or if other timers add too big delays, or if there's not enough threads, or time-consuming test elements prevent it.
Note: in many cases, Open Model Thread Group would be a better choice for generating the desired load profile
Note: if you alter timer configuration on the fly, then it might take time to adapt to the new settings. For instance, if the timer was initially configured for 1 request per hour, then it assigns incoming threads with 3600+sec pauses. Then, if the load configuration is altered to 1 per second, then the threads are not interrupted from their delays, and the threads keep waiting.

Although the Timer is called Precise Throughput Timer, it does not aim to produce precisely the same number of samples over one-second intervals during the test.

The timer works best for rates under 36000 requests/hour, however your mileage might vary (see monitoring section below if your goals are vastly different).
```
Since the PTT only takes absolute values we calculate for each proportion the **requests per second** that we desire:

| Thread Group 	| Proportion | Low (60) | Medium (240) | High (600) |
| ------------- | ---------- | -------- | ------------ | ---------- |
| Action 1 		| 10.650 %	 | 0.1065	| 0.426		   | 1.065      |
| Action 2 		| 23.075 %	 | 0.2308	| 0.9232	   | 2.3075     |
| Action 3 		| 41.925 %	 | 0.4193	| 1.6772  	   | 4.1925     |
| Action 4 		| 19.350 %	 | 0.1935	| 0.774	   	   | 1.935      |
| Action 5 		| 3.225 %	 | 0.0323	| 0.1292       | 0.3225     |
| Action 6 		| 1.775 %	 | 0.0178	| 0.0712       | 0.1775     |
| Total 		| 100 %		 | 1		| 2            | 10         |



Knowing the desired thoughput now we need to calculate how many threads we need to cover this throughput.
Using the Little's Law (https://loadtest.help/knowledge/littles-law.html):

$$ N = \Lambda * T $$

where:
- N = Number of concurrent items on the system (threads)
- lambda = Throughput 
- T = time that each thread goes in the system (average time)

N would be the number of threads that are are necessary **if** the average time was consistent. To account for that variable we introduce a value **k = 1.5** to make sure there are enough threads ready to process the request at all times.

To exemplify we use the "Low" scenario values to calculate each N value:

$$ N_{1} = \Lambda_{1} * T_{1} = \lceil 0.1065 * 130.5 \rceil = 14 $$
$$ N_{2} = \Lambda_{2} * T_{2} = \lceil 0.2308 * 10.1 \rceil = 3 $$
$$ N_{3} = \Lambda_{3} * T_{3} = \lceil 0.4193 * 30.2 \rceil = 13 $$
$$ N_{4} = \Lambda_{4} * T_{4} = \lceil 0.1935 * 70.1 \rceil = 14 $$
$$ N_{5} = \Lambda_{5} * T_{5} = \lceil 0.0323 * 23.33 \rceil = 1 $$
$$ N_{6} = \Lambda_{6} * T_{6} = \lceil 0.0178 * 6.5 \rceil = 1 $$

And applying the k value for the Low scenario:

| Thread Group      | req/min  | res/s  | T 		| N     | N * K |
| ----------------- | -------- | ------ | --------- | ----- | ----- | 
| Action 1 	        | 6.39     | 0.1065 | 130.5s    | 14 	| 21    |
| Action 2  		| 13.85    | 0.2308 | 10.1s     | 3  	| 5     |
| Action 3 		    | 25.16    | 0.4193 | 30.2s     | 13 	| 20    |
| Action 4 		    | 11.61    | 0.1935 | 70.1s     | 14 	| 21    |
| Action 5 		    | 1.94     | 0.0323 | 23.33s    | 1  	| 2     |
| Action 6          | 1.07     | 0.0178 | 6.5       | 1  	| 2     |

For the Medium scenario (240 requests/min):

| Thread Group      | req/min  | res/s  | T 		| N     | N * K |
| ----------------- | -------- | ------ | --------- | ----- | ----- | 
| Action 1 	        | 25.56    | 0.426  | 130.5s    | 56    | 84    |
| Action 2  		| 55.392   | 0.9232 | 10.1s     | 10    | 15    |
| Action 3 		    | 100.632  | 1.6772 | 30.2s     | 51    | 77    |
| Action 4 		    | 46.44    | 0.774  | 70.1s     | 55    | 83    |
| Action 5 		    | 7.75     | 0.1292 | 23.33s    | 4     | 6     |
| Action 6          | 4.272    | 0.0712 | 6.5       | 1     | 2     |

For the High scenario (600 requests/min):

| Thread Group      | req/min  | res/s  | T 		| N     | N * K |
| ----------------- | -------- | ------ | --------- | ----- | ----- | 
| Action 1 	        | 63.90    | 1.065  | 130.5s    | 139   | 209   |
| Action 2  		| 138.45   | 2.3075 | 10.1s     | 24    | 36    |
| Action 3 		    | 247.95   | 4.1925 | 30.2s     | 127   | 191   |
| Action 4 		    | 116.1    | 1.935  | 70.1s     | 136   | 204   |
| Action 5 		    | 19.35    | 0.3225 | 23.33s    | 8     | 12    |
| Action 6          | 10.65    | 0.1775 | 6.5       | 2     | 3     |

Note: Since this values are ceiled the thoughput is expected to be just a bit bigger than the theorical calculation

### Ramp-up

| Thread Group      | Low   | Medium | High   |
| ----------------- | ----- | ------ | ------ |
| Action 1 	        | 10.5s | 42s    | 104.5s |
| Action 2  		| 2.5s  | 7.5s   | 18s    |
| Action 3 		    | 10s   | 38.5s  | 95.5s  |
| Action 4 		    | 10.5s | 41.5s  | 102s   |
| Action 5 		    | 1s    | 3s     | 6s     |
| Action 6          | 1s    | 1s     | 1.5s   |


*The ramp-up period tells JMeter how long to take to "ramp-up" to the full number of threads chosen. If 10 threads are used, and the ramp-up period is 100 seconds, then JMeter will take 100 seconds to get all 10 threads up and running. Each thread will start 10 (100/10) seconds after the previous thread was begun. If there are 30 threads and a ramp-up period of 120 seconds, then each successive thread will be delayed by 4 seconds.*

*Ramp-up needs to be long enough to avoid too large a work-load at the start of a test, and short enough that the last threads start running before the first ones finish (unless one wants that to happen).* 

https://jmeter.apache.org/usermanual/test_plan.html

The ramp-up time is defined so each thread has a 0.5s interval between each other.
