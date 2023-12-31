# Splunk BOTS v2 Recap

This Splunk BOTS recap and walkthrough is based on the Version 3 event. You can download the botsv3 dataset from https://github.com/splunk/botsv3 and load into a Splunk instance, or you can sign up for an account at https://tryhackme.com and play along.


## Table of Contents
* [200 Series Question](https://github.com/chan2git/splunk-bots/tree/main/botsv3#200-series-questions)

    * [Q200: List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q200-list-out-the-iam-users-that-accessed-an-aws-service-successfully-or-unsuccessfully-in-frothlys-aws-environment)

    * [Q201: What field would you use to alert that AWS API activity has occurred without MFA?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q201-what-field-would-you-use-to-alert-that-aws-api-activity-has-occurred-without-mfa)

    * [Q202: What is the processor number used on the web servers?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q202-what-is-the-processor-number-used-on-the-web-servers)

    * [Q204: Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q204-bud-accidentally-makes-an-s3-bucket-publicly-accessible-what-is-the-event-id-of-the-api-call-that-enabled-public-access)

    * [Q205: What is Bud's username?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q205-what-is-buds-username)

    * [Q207: What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible?xt](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q206-what-is-the-name-of-the-s3-bucket-that-was-made-publicly-accessible)

    * [Q208: What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q208-what-is-the-fqdn-of-the-endpoint-that-is-running-a-different-windows-operating-system-edition-than-the-others)

    * [Q209: A Frothly endpoint exhibits signs of coin mining activity. What is the name of the second process to reach 100 percent CPU processor utilization time from this activity on this endpoint?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q209-a-frothly-endpoint-exhibits-signs-of-coin-mining-activity-what-is-the-name-of-the-second-process-to-reach-100-percent-cpu-processor-utilization-time-from-this-activity-on-this-endpoint)

    * [Q210: What is the short hostname of the only Frothly endpoint to actually mine Monero cryptocurrency?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q210-what-is-the-short-hostname-of-the-only-frothly-endpoint-to-actually-mine-monero-cryptocurrency)

    * [Q212: What is the name of the attack?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q212-what-is-the-name-of-the-attack)

    * [Q213: According to Symantec's website, what is the severity of this specific coin miner threat?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q213-according-to-symantecs-website-what-is-the-severity-of-this-specific-coin-miner-threat)

    * [Q214: What is the short hostname of the only Frothly endpoint to show evidence of defeating the cryptocurrency threat?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q214-what-is-the-short-hostname-of-the-only-frothly-endpoint-to-show-evidence-of-defeating-the-cryptocurrency-threatnk)

    * [Q215: What IAM user access key generates the most distinct errors when attempting to access IAM resources?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q215-what-iam-user-access-key-generates-the-most-distinct-errors-when-attempting-to-access-iam-resources)

    * [Q216: Bud accidentally commits AWS access keys to an external code repository. Shortly after, he receives a notification from AWS that the account had been compromised. What is the support case ID that Amazon opens on his behalf?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q216-bud-accidentally-commits-aws-access-keys-to-an-external-code-repository-shortly-after-he-receives-a-notification-from-aws-that-the-account-had-been-compromised-what-is-the-support-case-id-that-amazon-opens-on-his-behalf)

    * [Q217: AWS access keys consist of two parts: an access key ID (e.g., AKIAIOSFODNN7EXAMPLE) and a secret access key (e.g., wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY). What is the secret access key of the key that was leaked to the external code repository?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q217-aws-access-keys-consist-of-two-parts-an-access-key-id-eg-akiaiosfodnn7example-and-a-secret-access-key-eg-wjalrxutnfemik7mdengbpxrficyexamplekey-what-is-the-secret-access-key-of-the-key-that-was-leaked-to-the-external-code-repository)

    * [Q218: Using the leaked key, the adversary makes an unauthorized attempt to create a key for a specific resource. What is the name of that resource?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q202-what-is-the-processor-number-used-on-the-web-servers)

    * [Q219: Using the leaked key, the adversary makes an unauthorized attempt to describe an account. What is the full user agent string of the application that originated the request?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q219-using-the-leaked-key-the-adversary-makes-an-unauthorized-attempt-to-describe-an-account-what-is-the-full-user-agent-string-of-the-application-that-originated-the-request)
    
* [300 Series Question](https://github.com/chan2git/splunk-bots/tree/main/botsv3#300-series-questions)

    * [Q300: What is the full user agent string that uploaded the malicious link file to OneDrive?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q300-what-is-the-full-user-agent-string-that-uploaded-the-malicious-link-file-to-onedrive)

    * [Q301: What was the name of the macro-enabled attachment identified as malware?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q301-what-was-the-name-of-the-macro-enabled-attachment-identified-as-malware)

    * [Q302: What is the name of the executable that was embedded in the malware? Answer guidance: Include the file extension.](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q302-what-is-the-name-of-the-executable-that-was-embedded-in-the-malware)

    * [Q303: What is the password for the user that was successfully created by the user "root" on the on-premises Linux system?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q303-what-is-the-password-for-the-user-that-was-successfully-created-by-the-user-root-on-the-on-premises-linux-system)

    * [Q304: What is the name of the user that was created after the endpoint was compromised?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q304-what-is-the-name-of-the-user-that-was-created-after-the-endpoint-was-compromised)

    * [Q305: Based on the previous question, what groups was this user assigned to after the endpoint was compromised?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q305-based-on-the-previous-question-what-groups-was-this-user-assigned-to-after-the-endpoint-was-compromised)

    * [Q306: What is the process ID of the process listening on a "leet" port?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q306-what-is-the-process-id-of-the-process-listening-on-a-leet-port)

    * [Q307: What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q307-what-is-the-md5-value-of-the-file-downloaded-to-fyodors-endpoint-system-and-used-to-scan-frothlys-network)

    * [Q308: What port number did the adversary use to download their attack tools?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q308-what-port-number-did-the-adversary-use-to-download-their-attack-tools)

    * [Q309: Based on the information gathered for question 1, what file can be inferred to contain the attack tools?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q309-based-on-the-information-gathered-for-question-1-what-file-can-be-inferred-to-contain-the-attack-tools)

    * [Q310: During the attack, two files are remotely streamed to the /tmp directory of the on-premises Linux server by the adversary. What are the names of these files?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q310-during-the-attack-two-files-are-remotely-streamed-to-the-tmp-directory-of-the-on-premises-linux-server-by-the-adversary-what-are-the-names-of-these-files)

    * [Q311: The Taedonggang adversary sent Grace Hoppy an email bragging about the successful exfiltration of customer data. How many Frothly customer emails were exposed or revealed?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q311-the-taedonggang-adversary-sent-grace-hoppy-an-email-bragging-about-the-successful-exfiltration-of-customer-data-how-many-frothly-customer-emails-were-exposed-or-revealed)

    * [Q312: What is the path of the URL being accessed by the command and control server?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q310-during-the-attack-two-files-are-remotely-streamed-to-the-tmp-directory-of-the-on-premises-linux-server-by-the-adversary-what-are-the-names-of-these-files)

    * [Q313: At least two Frothly endpoints contact the adversary's command and control infrastructure. What are their short hostnames?](https://github.com/chan2git/splunk-bots/tree/main/botsv3#q313-at-least-two-frothly-endpoints-contact-the-adversarys-command-and-control-infrastructure-what-are-their-short-hostnames)


## 200 Series Questions

### Q200: List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment?

Logs regarding IAM users can be found within the sourcetype `aws:cloudtrail` and further narrowed by the field `IAMuser`. We can build the query below and output the values for the field `userName` to list out the usernames of IAM users that have accessed (successfully or unsuccessfully) Frothly's AWS environment.

```
index=botsv3 sourcetype=aws:cloudtrail userIdentity.type=IAMUser
| stats values(userName)
```
![Q200](./images/Q200_1.png)


**Answer: bstoll, btun, splunk_access, web_admin**



### Q201: What field would you use to alert that AWS API activity has occurred without MFA?

We know that there is a field within the sourcetype `aws:cloudtrail` called `eventType` which contains a value named `AwsApiCall`. We can first run the below query and see if there are any interesting fields associated with the returned events.

```
index=botsv3 sourcetype=aws:cloudtrail eventType=AwsApiCall
```



![Q201_1](./images/Q201_1.png)

![Q201_2](./images/Q201_2.png)

When examining the fields, there is a field called `userIdentity.sessionContext.attributes.mfaAuthenticated` with the value of `false`. Based on the lengthy and descriptive field name with the value of false, it is most likely associated with events that occured without MFA.

**Answer: userIdentity.sessionContext.attributes.mfaAuthenticated**


### Q202: What is the processor number used on the web servers?

The lab provided hint suggests using the sourcetype `hardware`.

We can simply first run the below query and see if any interesting fields or data is returned.

```
index=botsv3 sourcetype=hardware
```

![Q202_1](./images/Q202_1.png)

Right away, you can examine eiter in the event data or check the field `cpu_type` to see that the web servers use Intel Xeon CPU E5-2676, which the processor number is E5-2676.

**Answer: E5-2676**



## Q204: Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access?

For this question, it may be useful to refer to AWS documentation regarding S3 buckets and access control lists ("ACL") at https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html. From the documentation and other available resources, we know that the keywords putbucketacl or the command `put-bucket-acl` may be relevant and useful to incldue in our SPL query as it refers to a AWS S3 API call used to set or update the ACL permissions of a S3 bucket. Since we know Bud accidentally made a S3 bucket public, putbucketacl (or `put-bucket-acl`) will likely help us hone in on the event.

```
index=botsv3 sourcetype=aws:cloudtrail (putbucketacl OR "put-bucket-acl")
```

![204_1](./images/Q204_1.png)

We were able to return 2 events. We can either expand some of the interesting fields within the event data or sift through any interesting fields, such as `requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.xmlns:URI`, which will show that the bucket is accessible to all users.

![204_2](./images/Q204_2.png)

![204_3](./images/Q204_3.png)

This event corresponds to the Event ID of ab45689d-69cd-41e7-8705-5350402cf7ac.

**Answer: ab45689d-69cd-41e7-8705-5350402cf7ac**


### Q205: What is Bud's username?

We can modify the query from Q204 to simply add the command `table` against the field `userName`, which gives us the one unique value of bstoll - the 'b' likely stands for Bud and is likely Bud's username.

```
index=botsv3 sourcetype=aws:cloudtrail (putbucketacl OR "put-bucket-acl")
| table userName
```
![205_1](./images/Q205_1.png)


**Answer: bstoll**


## Q206: What is the name of the S3 bucket that was made publicly accessible?

Using the same query from Q204, there is a field called `requestParameters.bucketName` with the value of `frothlywebcode`.

**Answer: frothlywebcode**

### Q207: What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible? 

To view more specific logs about S3 buckets, we'll need to look into the sourcetype `aws:s3:accesslogs`. We know that bucket name is frothlywebcode. When uploading data or a resource to a server, we know that the HTTP method or operation is a PUT (and not GET), and the http status code is typically 200. With this information and examining the fields within the sourcetype `aws:s3:accsslogs`, we build the below query and output the field `request_uri` which will contain the file name.

```
index=botsv3 sourcetype=aws:s3:accesslogs bucket_name=frothlywebcode operation="REST.PUT.OBJECT" http_status=200
| table request_uri
```
![207_1](./images/Q207_1.png)

From our table results, it is most likely "OPEN_BUCKET_PLEASE_FIX.txt" based on the urgency and unusual file name.

**Answer: OPEN_BUCKET_PLEASE_FIX.txt**.



### Q208: What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?

To find the answer to this, we'll need to search through a sourcetype that contains information on each endpoint/host and what their corresponding OS is. `winhostmon` would be an excellent sourcetype and contains the field `source` which has the value of `operatingsystem` (and contains the nested fields `OS`) and the field `Host`. We can use this information to run the below query and see if we get any interesting results.

We'll display the extracted field `OS` and the field `Host` as a table and ensure that we remove any duplicate values from `Host`.

```
index=botsv3 sourcetype=winhostmon source=operatingsystem
| table OS, host
| dedup host
```

![208_1](./images/Q208_1.png)

When viewing the table results, we can clearly see that most machines are running Microsoft Windows 10 Pro while only one machine (BSTOLL-L) is running Microsoft Windows 10 Enterprise. This seems to be the one machine that is running something different.  We can take this information and search it in the sourcetype `wineventlog` and see if we can find any interesting fields that may point to what the FQDN is.

```
index=botsv3 sourcetype=wineventlog BSTOLL-L
```

![208_2](./images/Q208_2.png)


**Answer: BSTOLL-L.froth.ly**



### Q209: A Frothly endpoint exhibits signs of coin mining activity. What is the name of the second process to reach 100 percent CPU processor utilization time from this activity on this endpoint? 

The guidance for this question suggests trying to search keywords related to processors and utilization to see if we can figure out which sourcetype might contain this information. The hint for this question suggests that we use a 1:10 event sampling for the initial query to avoid any search errors.

With event sampling set to 1:10, we can simply run the generic command below and see if we get anything returned. Remember, we're interested in values that reference 100% which may be for the fields related to processor utilization. Instead of "100%", let's try "100" first and be more detailed if needed.

```
index-botsv3 100
```

![209_1](./images/Q209_1.png)

![209_2](./images/Q209_2.png)



From the results, if we examine the field sourcetype, we can see that there's a interesting value called `PerfmonMk:Process`. A quick google search PerfmonMk:Process will return results for Splunk documentation for sourcetype add-ons for Windows which describes PerfmonMk:Process as having information about processes running on the system provided. This seems to be an appropriate sourcetype for us to search through next.

Notice that the Splunk documentation mentions Perfmon:CPU/PerfmonMk:CPU which is described as providing CPU usage statistics. However, this sourcetype doesn't seem to be used in this environment.

Within the sourcetype `PerfmonMk:Process`, there are interesting fields called `process_cpu_used_percent`, `process_name`, and `host`. We can build the below query to search for events where the CPU is utilized at 100% and return to us a table showing us the timeline (old to new) of the process name and it's corresponding host.

```
index=botsv3 sourcetype="Perfmon:Process" process_cpu_used_percent=100
| table _time process_name, host
| sort _time
```

![209_3](./images/Q209_3.png)

When examining the results, we see that the second process name to reach 100% CPU utilization is chrome#5.

**Answer: chrome#5**





### Q210: What is the short hostname of the only Frothly endpoint to actually mine Monero cryptocurrency?

I think by now we can guess that it has to be BSTOLL-L as it's this host machine that's exhibiting weird activity. Based on table result from Q209, it appears to be BSTOLL-L.

**Answer: BSTOLL-L**


### Q211: Using Splunk's event order functions, what is the first seen signature ID of the coin miner threat according to Frothly's Symantec Endpoint Protection (SEP) data?

The sourcetype associated with Symantec Endpoint Protection is hinted to us as `symantec:ep:security:file`. Within the sourcetype, it appears that all events are related to the coin miner threat. We can use the below query to display the results as a table and sort it from old to new and show the corresponding field `CIDS_Signature_ID` which houses values for the signature ID.

```
index=botsv3 sourcetype="symantec:ep:security:file"
| table _time, CIDS_Signature_ID
| sort _time
```

![211_1](./images/Q211_1.png)

We actually see that both the signature ID of 30356 and 30358 alerted at the same time. When trying both answers, 30358 is considered the correct answer.

**Answer: 30358**


## Q212: What is the name of the attack?

We can run the below query specifcying the signature ID of 30358 and display the results as a table and highlighting value for `Event_Description`, which references the attack as "JSCoinminer Download 8"

```
index=botsv3 sourcetype="symantec:ep:security:file"
| table Event_Description
| dedup Event_Description
```

![212_1](./images/Q212_1.png)

**Answer: JSCoinminer Download 8**

## Q213: According to Symantec's website, what is the severity of this specific coin miner threat?

First, we need to understand that Symantec was acquired by Broadcom to avoid any confusion on why searches on google keep pointing to a Broadcom domain.

When googling for "Symantec JSCoinminer Download 8", we see that Symantec (now Broadcom) indicates the severity level as medium, which is not the right answer at the time botsv3 event was created.

So instead, we can run the below query to display the field `severity` rating as a table and get the answer of high.

![213_1](./images/Q213_1.png)

![213_2](./images/Q213_2.png)


**Answer: medium**


## Q214: What is the short hostname of the only Frothly endpoint to show evidence of defeating the cryptocurrency threat? 

If we think back to Q212, not only did the event description reference the name of the attack, but that the attack and traffic has been blocked (which is our evidence that there's a host that successfully fended off the attack).

We can run the below query and display the value for `Host_Name`, which will tell us that the host BTUN-L successfully fended off the attack.

```
index=botsv3 sourcetype="symantec:ep:security:file"
| table Event_Description, Host_Name
| dedup Event_Description
```

![214_1](./images/Q214_1.png)

**Answer: BTUN-L**



### Q215: What IAM user access key generates the most distinct errors when attempting to access IAM resources?

The question asks us to find the IAM user access key with the most distinct errors when trying to access IAM resources. Based on this, we know that we'll need to implement the `stats dc` command to identify the distinct count.

Within the sourcetype `aws:cloudtrial`, we are interested in the fields `errorMessage` (extracted field which will show the various types of errors), `userIdentity.accessKeyID` (which shows the IAM user access key), `eventSource` (which details which AWS resource is involved), and `errorCode` (which provides the generic success or error value of the event).

Knowing this, we can build the below query to search through cloudtrail logs for events related to IAM resource where the error code excludes successful attempts, and distintly count the quantity of unique error messages sorted by user access key and their corresponding user.


```
index=botsv3 sourcetype=aws:cloudtrail eventSource="iam.amazonaws.com" errorCode!=success
| stats dc(errorMessage) by userIdentity.accessKeyID, user
```

![215_1](./images/Q215_1.png)

From our table results, we can see that the user access key AKIAJOGCDXJ5NW5PXUPA has the most distinct errors.

**Answer: AKIAJOGCDXJ5NW5PXUPA**



### Q216: Bud accidentally commits AWS access keys to an external code repository. Shortly after, he receives a notification from AWS that the account had been compromised. What is the support case ID that Amazon opens on his behalf?

Through the course of completing this BOTS event and sifting through various fields and their values, we know that the Bud is the user BSTOLL, who has the email bstoll@froth.ly. AWS likely notified Bud by email (and per hint which suggests searching through `stream:smtp`) that the account may have been compromised. The support ID is likely found within this email.

To find this email, we can search through the sourcetype `stream:smtp` and add in the generic keywords bstoll@froth.ly, and case aws and see if anything interesting is returned. We'll include wildcards for aws and case just to ensure we aren't too exclusive.

```
index=botsv3 sourcetype="stream:smtp" bstoll@froth.ly *aws* *case*
```


![216_1](./images/Q216_1.png)


We get one event returned, and if we expand the event's content body, we can see that AWS opened the ticket number 5244329601.

**Answer: 5244329601**


### Q217: AWS access keys consist of two parts: an access key ID (e.g., AKIAIOSFODNN7EXAMPLE) and a secret access key (e.g., wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY). What is the secret access key of the key that was leaked to the external code repository?

Within the email, AWS states that the access key alongside the corresponding secret key is available online at the specified github repo. If we access the repo, we see that the secret access key is Bx8/gTsYC98T0oWiFhpmdROqhELPtXJSR9vFPNGk.

![217_1](./images/Q217_1.png)


**Answer: Bx8/gTsYC98T0oWiFhpmdROqhELPtXJSR9vFPNGk**



### Q218: Using the leaked key, the adversary makes an unauthorized attempt to create a key for a specific resource. What is the name of that resource?

We know that the leaked key used is AKIAJOGCDXJ5NW5PXUPA and that the adversary made a failed attempt to create a key. Knowing this, we can build the below query and see if we find anything interesting.

```
index=botsv3 sourcetype=aws:cloudtrail userIdentity.accessKeyId=AKIAJOGCDXJ5NW5PXUPA eventName=CreateAccessKey
```

![218_1](./images/Q218_1.png)

One event is returned, and if we examine errorMessage, we see that the adversary attempted to create keys for the resource nullweb_admin

**Answer: nullweb_admin**

### Q219: Using the leaked key, the adversary makes an unauthorized attempt to describe an account. What is the full user agent string of the application that originated the request?

Similar to Q218's query, we're going to search for events associated to the leaked key AKIAJOGCDXJ5NW5PXUPA but with the field `eventName` now pointing to the value of `DescribeAccountAttributes`.


```
index=botsv3 sourcetype=aws:cloudtrail userIdentity.accessKeyId=AKIAJOGCDXJ5NW5PXUPA eventName=DescribeAccountAttributes
```

![219_1](./images/Q219_1.png)

We get a single event returned, and if we examine the userAgent, we see that the user agent used is ElasticWolf/5.1.6.

**Answer: ElasticWolf/5.1.6**


## 300 Series Questions




### Q300: What is the full user agent string that uploaded the malicious link file to OneDrive?

The hint suggests using `ms:o365:management` as the sourcetype. Within this sourcetype, there are a few fields we can use to narrow in on relevant events. The fields `Workload` pertain to which O365 product, `SourceFileExtension` pertains to the file's extension type, and `Operation` pertains to the nature of operation/action. Knowing this, we can build the below query and return as a table the resulting values for the field `UserAgent` and see if we get any interesting results.

```
index=botsv3 sourcetype="ms:o365:management" Workload=OneDrive SourceFileExtension=lnk Operation=FileUploaded
| table UserAgent
```

![220_1](./images/Q220_1.png)

Interestingly, we get 1 result back and the user agent string mentions Fedora/Naenara Browser. Fedora is a widely-used and highly recogonized community-driven and open-source Linux distribution. While the distro isn't some obscure Linux flavor, it's not a Linux distro you'd expect to see within a professional enterprise environment used on a employee endpoint device/host. Additionally, a google search of Naenara Browser indicates that it is a North Korean intranet web browser - definitely unusual!

![220_2](./images/Q220_2.png)

**Answer: Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4**



### Q301: What was the name of the macro-enabled attachment identified as malware?

The hint provided suggests searching through `stream:smtp` as the sourcetype, which makes sense given that the question's keywords macro-enabled attachment likely suggests an email attachment. Given that we've observed the Frothly environment utilizing O365 products, it's reasonable to assume that they are using Microsoft Outlook. A key behavior in Outlook is when it detects an attached file as malware, it'll actually rename the file as Malware Alert Text.txt.

We can run the general query below and see if we get any interesting events.

```
index=botsv3 sourcetype="stream:smtp" *malware* *alert*
```

![221_1](./images/Q221_1.png)

We get only a single event returned, and if we example the extracted field attach_filename, we see the file name of Malware Alert Text.txt, which is likely the malicious file that was renamed by Outlook. 

In order to figure out the original file name, we'll have to inspect the event and it's content closer. When examining the field content, we don't see the original file name readily apparent. But there is a string that appears to be encoded in base64. If we decode the base64 string, we get what appears to be a .xlsm file, which is an Excel macro-enabled file extension.

![221_2](./images/Q221_2.png)

![221_3](./images/Q221_3.png)

**Answer: Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm**


### Q302: What is the name of the executable that was embedded in the malware?

The provided hint suggests using `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` as the sourcetype.

We can build the below generic query with the malicious file name and see if anything interesting is returned. 

```
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" Frothly-Brewery-Financial-Planning-FY2019-Draft
```


![222_1](./images/Q222_1.png)


We get a single event correlating to the malicious file name, and we see that there's an additional executable file named HxTsr.exe.

**Answer: HxTsr.exe**

### Q303: What is the password for the user that was successfully created by the user "root" on the on-premises Linux system?

The provided hint suggests using one of the osquery logs for the sourcetype. `osquery:results` logs command lines, which will be helpful as we need to look for commands associated with creating a new account in Linux. We can build the query below and add in the words "adduser" or "useradd" with wildcards, which should capture a part of a command line string used to create new accounts. We'll also add the field `decorations.username` with the value of `root` to narrow in on events associated with the root user.

```
index=botsv3 sourcetype="osquery:results" "decorations.username"=root (*adduser* OR *useradd*)
```

![223_1](./images/Q223_1.png)

A single event is returned, and if we examine the event details and expand the columns field, we see that there is a sub field called cmdline which shows a Linux command line related to creating a new user and setting the password.

**Answer: ilovedavidverve**


### Q304: What is the name of the user that was created after the endpoint was compromised?

The question provided hint suggests using `WinEventLog:Security` as the source type, which hints to us that the action of creating a new user occured in a Windows environment. When a new user is created in Windows, it generates a EventCode of 4720. Knowing this, we can build the generic query below and see if anything interesting is returned.

```
index=botsv3 source="WinEventLog:Security" EventCode=4720
```

![224_1](./images/Q224_1.png)

Our query returns 1 event, and if we examine the single event's details, we see that there is a new user created in the name of svcvnc.

**Answer: svcvnc**


### Q305: Based on the previous question, what groups was this user assigned to after the endpoint was compromised?

We can use the below generic query and throw in the user name svcvnc and table the field `Group_Name` and see which groups it's associated to. We can see the notable resulting values are Administrators and Users. This makes sense as the threat actor would likely add this newly created account to the Admin group to maintain persistence and escalate privileges.


```
index=botsv3 source="WinEventLog:Security" svcvnc
| table Group_Name
```

![225_1](./images/Q225_1.png)


If we want to double check and examine the event details, we can re-run the query without the table command. We'll see that there are events which detail what appears to be a PowerShell command which adds svcvnv to the local group administrators.


![225_2](./images/Q225_2.png)



**Answer: Administrator, User**


### Q306: What is the process ID of the process listening on a "leet" port?

The question provided hint suggests seaching through the sourcetype osquery (in this case, `osquery:results`) for open ports found on the Linux host called hoth. The question also provided hints and asked what numerical values are assocaited to the phrase "leet". A simple google search on the word leet (or if you're familiar with the leetspeak) would indicate the association to the number 1337.

Knowing this, we can build the below query and see if anything interesting is returned. The field `columns.port` is an extracted field pertaining to the port number, so we can set the value to `1337`.

```
index=botsv3 host=hoth sourcetype="osquery:results" "columns.port"=1337
```

![306_1](./images/Q306_1.png)


We get a single event returned, and if we expand the columns field we see that there is a extracted field called pid (columns.pid) with a value of 14356.

**Answer: 14356**


### Q307: What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?

First, we should figure out what Fyodor's hostname is. Simply running the query `index=botsv3 Fyodor` and checking the values for the field `host` will reveal that the hostname is `FYODOR-L`. Next, we know that md5 hash values can be found within the sourcetype `xmlwineventlog:microsoft-windows-sysmon/operational`. We can further narrow in on our query by setting the field `EventDesciption` to `Process Create` to account for the fact that we are looking for events in which a file/process was likely executed to scan the network. 

We can table the results to highlight the fields `app` (pertains to the file name/application), `cmdline` (it's likely the threat actor executed a command to download/execute the malicious file and potentially pass parameters for the network scan), and `hashes` (pertaining to MD5 hash values).

With this information, we can build the below query:

```
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" host="FYODOR-L" direction=inbound EventDescription="Process Create"
| table app, cmdline, hashes
```

![307_1](./images/Q307_1.png)


We get a total of 158 events and could manually sift through and see if we find anything interesting. On page 8, we see a cmdline value that reads `C:\windows\temp\hdoor.exe" -hbs 192.168.9.1-192.168.9.50 /b /m /n` associated to the file name hdoor.exe. The file name is suspicious and the command line is reminiscent of network scanning based on the strings "192.168.9.1-192.168.9.50". It reads like passing in a range of internal private network IP addresses to scan for! Using the hash value as the answer indicates this is indeed the malicious file used to scan the Frothly network.


![307_2](./images/Q307_2.png)



**Answer: 586Ef56F4D8963DD546163AC31C865D7**


### Q308: What port number did the adversary use to download their attack tools?

The question provided hints that a lot of malicious activity occured on Fyodor's endpoint and we can start with his host and that downloads can occur on various protocols (HTTP, TCP, FTP,etc). We'll need to think about this carefully and draw on context clues.

Most file transfers/downloads occur over HTTP, so we can begin our search with `stream:http` as our sourcetype. We also know that we can use `FYODOR-L` as the host. We know that the field `http_method` should be assigned the value of `GET` to account for download activity. Let's use this information to build a query and print out the available matching port numbers and their counts to see if we can find anything interesting.

```
index=botsv3 sourcetype="stream:http" host="FYODOR-L" http_method=GET
stats count by dest_port
```
![308_1](./images/Q308_1.png)


We see that there are three port numbers returned to us: 3333 (with a count of 1), 80 (with a count of  475), 8080 (with a count of 2). Port 3333 appears unusual in this case. While there are needs to use ephemeral port numbers, a single use of port 3333 feels a bit off and should prompt us to look closer at this one singular event and see what URI path and IP address is associated with it. We can modify our query to now read:

```
index=botsv3 sourcetype="stream:http" host="FYODOR-L" http_method=GET dest_port=3333
| table uri_path
```
![308_2](./images/Q308_2.png)

Our results show us that port 3333 was used to download a file called logos.png from what appears to be an external IP address, which is very unusual.

**Answer: 3333**


### Q309: Based on the information gathered for question 1, what file can be inferred to contain the attack tools?

See query table results from Q308.

**Answer: logos.png**

### Q310: During the attack, two files are remotely streamed to the /tmp directory of the on-premises Linux server by the adversary. What are the names of these files?

Solution needs further analysis and understanding. Check back for update.

Logs dealing with the Linux server should correlate with the `osquery:results` sourcetype and we should search for the keyword /tmp. We'll notice that there are at least 7 files associated with the unauthorized user tomcat8; 2 of which are colonel and definitelydontinvestigatethisfile.sh.

**Answer: colonel,definitelydontinvestigatethisfile.sh**


### Q311: The Taedonggang adversary sent Grace Hoppy an email bragging about the successful exfiltration of customer data. How many Frothly customer emails were exposed or revealed?

We can run the general query below to search through the smtp logs with events that contain the keyword Hoppy.

```
index=botsv3 sourcetype="stream:smtp" *hoppy*
```

![311_1](./images/Q311_1.png)

We are returned with 47 events. If we sift through the events, we'll find an email in which Grace forwards an external email to her colleagues panicking over the customer data breach, in which 8 customer emails were exposed.

**Answer: 8**


### Q312: What is the path of the URL being accessed by the command and control server?

The hint provided for this question suggests that we search within the sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, or review the PowerShell scripts executed on various Frothly host machines. Based on this, we can deduce that we should be examining unusual PowerShell scripts executed on a potentially compromised user.

Instead of searching through Sysmon, we'll search through the source for PowerShell `WinEventLog:Microsoft-Windows_PowerShell/Operational`. While there are a few compromised Frothly machines, let's focus on one at a time and move on/adjust if needed. In this case, we'll start with the host `FYODOR-L` since Fyodor's machine seems to be the star of this question set. PowerShell command scripts could captured in the field `Message`, and we know from the question that a URL is involved. This means that we should narrow our search by setting the value of `*/*` to `Message`. We don't know what the URL is yet, but we can assume that it's in the format of "wildcard/wildcard". With this information, we can build the below query:

```
index=botsv3 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" host="FYODOR-L" Message="*/*"
```


![312_1](./images/Q312_1.png)

Six events are returned, which is pretty good if we're going to manually sift through the strings found in the extracted field of Message. When manually looking at the Message string, we can see that there are a few URLs that were accessed, such as "/news.php", "/lohin/process.php", etc. Using trial and error, we can determine that the correct answer is "/admin/get.php".

![312_2](./images/Q312_2.png)


**Answer: /admin/get.php**

### Q313: At least two Frothly endpoints contact the adversary's command and control infrastructure. What are their short hostnames?

We can actually revise Q312's query and display as a table which hosts match the events:

```
index=botsv3 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" Message="*/*"
| table host
| dedup host
```

![313_1](./images/Q313_1.png)

We are returned with two unique values for `host`: FYODOR-L and ABUNGST-L.

**Answer: FYODOR-L,ABUNGST-L**