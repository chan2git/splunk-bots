# Splunk BOTS v1 Recap

## Scenario 1: Web Site Defacement

### Q1: What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

First, we need to identify the IP address that belongs to our web server, which is likely what the threat group is scanning. We can run the below SPL query with the pipe command to return the destination IP address (`dest_ip`) with the highest hits, which is likely indicative of a web server.

```
index="botsv1" sourcetype="stream:http"
| top dest_ip
```

After running this SPL query, we see that the IP address with the most hits is `192.168.250.70`.

![ss1](./botsv1/images/ss1.png)

We can double check and confirm that this is in fact the IP address that belongs to `imreallynotbatman.com` by adding the IP address into the query, and then checking what data it is most commonly associated with in the `site` field. We'll see that it is most commonly associated to `imreallynotbatman.com`.

```
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70"
| top site
```
![ss2](./botsv1/images/ss2.png)


Using this information, we are now interested to know which `src_ip` has the highest hits to `192.168.250.70`, which may be indicative of web scanning and thus our threat actor. We can run the below SPL query and pipe in the top `src_ip` command, which will reveal `40.80.148.42` as the top count (substantially more than the others).

```
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" 
| top src_ip
```
![ss3](./botsv1/images/ss3.png)

With this piece of information, we can run the below SPL query and see what interesting information we can find in the results. Notably, some of the results contain a `src_headers` field which mention "Acunetix Web Vulnerability Scanner - Free Edition" - this confirms that the IP address `40.80.148.42` is conducting web vulnerability scanning and belongs to the threat actor.


```
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" src_ip="40.80.148.42"
```

![ss4](./botsv1/images/ss4.png)

![ss5](./botsv1/images/ss5.png)

#### Answer: 40.80.148.42 

### Q2: What company created the web vulnerability scanner used by Po1s0n1vy?

Based on the information we found in the `src_header` field that is associated to the IP address (40.80.148.42) of the threat actor, the company that created the web vulnerability scanner being used is **Acunetix**.

See Q1 Solution.

#### Answer: Acunetix


### Q3: What content management system is imreallynotbatman.com likely using?

We can filter some of the results from Q1's SPL query by narrowing in on successful HTTP GET requests (status code 200) and see if we find anything interesting that may indicate the CMS. Using the below query, "Joomla" is mentioned several times in the same string as content management. An external search of Joomla indicate that it is a CMS. 


```
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" src_ip="40.80.148.42" status=200
```

![ss6](./botsv1/images/ss6.png)

![ss7](./botsv1/images/ss7.png)

![ss8](./botsv1/images/ss8.png)

#### Answer: Joomla



### Q4: What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

If we assume our server downloaded the malicious file, then we know that our server can be considered the source IP address. We also know that downloads utilize the HTTP GET method. We can build the below SPL query and see if we find anything interesting.

```
index="botsv1" sourcetype="stream:http" src_ip="192.168.250.70" http_method=GET
```

Glancing at the results, we see that some hits contain a `request` field referencing the HTTP GET method used for a file named `poisonivy-is-coming-for-you-batman.jpeg`, which is likely the the file that defaced the `imreallynotbadman.com` website.

![ss13](./botsv1/images/ss13.png)

#### Answer: poisonivy-is-coming-for-you-batman.jpeg




### Q5: This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

When using Q4's SPL query, other interesting values are observed in the results. Notably, the `site` field associated with the HTTP GET method referencing `poisonivy-is-coming-for-you-batman.jpeg` has the value pointing to `prankglassinebracket.jumpingcrab.com`. This is likely the fully qualified domain that is resolved from the malicious IP address.

See solution to Q4.


#### Answer: prankglassinebracket.jumpingcrab.com


### Q6: What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

So far up to this point we've identified two malicious IP addresses. `40.80.148.42` has been associated to web vulnerability scanning and `23.22.63.114` has been associated to malicious files hosted on a domain. Based on this and if we had to pick one, it is likely `23.22.63.114`.

#### Answer: 23.22.63.114


### Q8: What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

We know that login-related events use the HTTP GET method, so we can build our SPL query to also include `http_method=POST` to narrow our data in the sourcetype `stream:http` and for our IP address `192.168.250.70`. We can also assume that the brute force password attack is likely generating several hits coming from one singular IP address (assuming that only 1 IP address is involved).Login event data may be logged under the `form_data` field. 

Knowing this, we can build the below SPL query to return to us a table that shows us the `form_data` values, the `uri` values (which can provide context on the page the HTTP GET method was used on and may come in handy later), and the event's associaed `src_ip`.

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST 
| stats count by src_ip, form_data, uri
```

Our table shows us that there are several results tied to the source IP address `23.22.63.114` which seems to be attempting multiple login attempts with the username "admin" and various passwords at the `uri` field value of `/joomla/administrator/index.php`. What this tells us is that the threat actor is conducting a brute force password attack on a administrator page from the source IP address of `23.22.63.114`.

![ss9](./botsv1/images/ss9.png)


#### Answer: 23.22.63.114


### Q9: What is the name of the executable uploaded by Po1s0n1vy?

For this question, we'll need to change our sourcetype to `fgt_utm`. We know that the threat actor's IP address is `40.80.148.42` and we are looking for some sort of executable file. Based on what we know, we can build the below SPL query and include a wildcard * for .exe (a common executable file extension).

```
index="botsv1" sourcetype="fgt_utm" srcip="40.80.148.42" *.exe
```

Our results will show us that there is a field named `filename` with the value `3791.exe` that is associated with the source IP address that belongs to the threat actor. Clicking on the `filename` field to expand it shows that `3739.exe` is the only executable file, so this is likely the file that was uploaded by the theat actor.

![ss11](./botsv1/images/ss11.png)

![ss12](./botsv1/images/ss12.png)

#### Answer: 3791.exe



### Q10: What is the MD5 hash of the executable uploaded?

Now that we know the malicious file name, we can update our SPL query to narrow in on `3791.exe`. In the results, we notice an interesting field called `file_hash`. Viewing the details for this field reveals that value of `ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d`.

![ss14](./botsv1/images/ss14.png)

We might be tempted to think that this is the correct answer but this string contains 64 characters. We know md5 hash strings contain only 32 characters, so this cannot be our correct answer.

We can try to find the malicious executable file in a different `sourcetype` like `xmlwineventlog:microsoft-windows-sysmon/operational` (Windows Sysmon) as it is plausible that the file may have been executed/opened by command line and it is common to record hashes of all files executed. We can use the below SPL query and see if we can find anything interesting.

```
index="botsv1" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "3791.exe"
```


We can (if it hasn't already) filter in and select a field called `CommandLine` and see that there is a value that matches our malicious file (`3791.exe`). When we tag on `"CommandLine="3791.exe"` to our query to further hone on, we get 1 result that has the `MD5` field with the value of `AAE3F5A29935E6ABCC2C2754D12A9AF0`.

![ss16](./botsv1/images/ss16.png)

#### Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0





## Q11: GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

We can search the malicious IP address `23.22.63.114` in VirusTotal and see if there are any other files associated to the threat actor's domain. When viewing and expanding on the details for the file called `MirandaTateScreensaver.scr.exe`, we can see it has a SHA256 hash value of `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8`

![ss17](./botsv1/images/ss17.png)


![ss18](./botsv1/images/ss18.png)


#### Answer: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8



### Q12: What special hex code is associated with the customized malware discussed in question 11?

Splunk BOTSv1 provides a hint that we'll need to do further external research somewhere on VirusTotal to identify the associated hex code. Wthin the Community Tab, we see the hex value of `53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21`

![ss19](./botsv1/images/ss19.png)

#### Answer: 53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21



### Q14: What was the first brute force password used?

To build out this SPL query, we'll use the SPL query from Q8 but now tag on `src_ip="23.22.63.114"` and `uri=/joomla/Administrator/index.php` to further hone in on the brute force attack.

We'll also want to return a table that sorts the time from earliest to oldest and associates the string used for the brute force attack to the malicious IP address. Using the format of the values found inside of the `form_data` field, we can use RegEx to extract the string the threat actor used for the passwords. Using the SPL query below, we see that the first string used for the bruteforce password attack is `12345678`.

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="23.22.63.114" http_method=POST uri=/joomla/Administrator/index.php
| rex field=form_data "passwd=(?<string>\w+)"
| sort _time
| table  _time src_ip string
```

![ss20](./botsv1/images/ss20.png)

#### Answer: 12345678




### Q15: One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

There are multiple ways to approach this. One way would be to locate a list of all Coldplay songs (from Wikipedia, etc) and paste them into a column (e.g. column A) within Microsoft Excel. You can then use the function `=IF(LEN(A:A) = 6, "Contains 6 characters", "Does not contain 6 characters")
` in the adjacent column (e.g. column B) and let Excel determine which cells have six characters. You can then filter only for rows indicated as having six characters.

From the filtered results, we may notice that some songs (`J-Hope`, `U.F.O.`) were considered to have six characters even though they consisted of special characters. Technically, they do contain six characters it seems the threat actor did not utilize any special characters in their brute force password attack so we will exclude `J-Hope` and `U.F.O.`.

What we're left with are `Aliens`, `Broken`, `Church`, `Clocks`, `Murder`, `Ocean`, `Shiver`, `Sparks`, `Wizkid`, and `Yellow`.


![ss21](./botsv1/images/ss21.png)


Taking note of the 10 Coldplay song titles with six characters (excluding special characters), we can modify our previous SPL query from Q14. Using RegEx, we'll want to identify any case-insensitive strings submitted as a password that are six characters in length. We'll take those RegEx matches and then search/compare them in a list that we'll populate with the aforementioned 10 Coldplay song titles and display the results in a table.

After running the below query, we see that there is a match to `yellow`.

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="23.22.63.114" http_method=POST uri=/joomla/Administrator/index.php
| rex field=form_data "(?i)passwd=(?<string>[a-zA-Z]{6})"
| search string IN (Aliens, Broken, Church, Clocks, Murder, Oceans, Shiver, Sparks, Wizkid, Yellow)
| table src_ip string
```


![ss22](./botsv1/images/ss22.png)

#### Answer: yellow



### Q16: What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

Let's think about this one carefully. We know that the threat actor completed a brute force password attack, of which there is a possibility that all but one string worked. The one string that works may stand out to us when viewing log data in that it may have been used the most frequent in comparison to other strings which may have only been used once as part of the brute force. We wouldn't expect to see multiple counts of the same failed string (unless the threat actor conducted multiple brute force password attacks that utilized overlapping strings, but we'd be able to deduce that).

We can use the below SPL query to sort by the strings attempted by frequency and see if theres any that has been uniquely used more frequently than others. We'll also omit the malicious IP address from our query for now as we may want to account that the correct password is used by others (e.g. authorized users).

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri=/joomla/Administrator/index.php
| rex field=form_data "passwd=(?<string>\w+)"
| stats count by string
| sort - count
| table string, count
```

![ss24](./botsv1/images/ss24.png)



We can see from the results that all strings but one have a count of 1, while `batman` has a count of 2. Based on these results, `batman` appears to be the correct password.

#### Answer: batman




### Q17: What was the average password length used in the password brute forcing attempt? (Round to the closest whole integer)

We can modify the SPL query from Q14 and utilize the `eval` and `stats` function to determine the average lengnth. Using the below query, we see that the average string length for the brute force password attack rounded to the closest whole integer is 6.


![ss25](./botsv1/images/ss25.png)


#### Answer: 6




### Q18: How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? (Round to 2 decimal places)

We know that `batman` appears to be the correct password and that it was utilized twice - once during the brute force attempt and subsuqently once more as the potential compromised login. We can build the below SPL query to return results for only these two events and then apply the `transaction` and `table` function to calculate the elapsed time and present as a table. Using the SPL query below, 92.17 seconds elapsed.

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*passwd*batman*
| rex field=form_data "passwd=(?<string>\w+)"
| transaction string
| table duration
```

![ss23](./botsv1/images/ss23.png)


#### Answer: 92.17


### Q19: How many unique passwords were attempted in the brute force attempt?

Using the SPL query from Q14, we can see that there were 412 events/statistic results - one for each unique attempted string during the brute force password attack.

See solution to Q14.

#### Answer: 412



## Scenario 2: Ransomware



### Q0: What was the most likely IPv4 address of we8105desk on 24AUG2016?



#### Answer: 



### Q200: What was the most likely IPv4 address of we8105desk on 24AUG2016?



#### Answer: 




### Q201: Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. (No puinctuation, just 7 digits)



#### Answer: 



### Q202: What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?



#### Answer: 





### Q203: What was the first suspicious domain visited by we8105desk on 24AUG2016?



#### Answer: 




### Q206: Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?



#### Answer:



### Q209: The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

#### Answer:



### Q210: The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?



#### Answer: 



### Q211: Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?



#### Answer: 



