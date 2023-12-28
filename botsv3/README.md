# Splunk BOTS v2 Recap

This Splunk BOTS recap and walkthrough is based on the Version 3 event. You can download the botsv3 dataset from https://github.com/splunk/botsv3 and load into a Splunk instance, or you can sign up for an account at https://tryhackme.com and play along.


## Table of Contents
* 200 Series Question
* 300 Series Question


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


### Q202: What is the processor number used on the web servers? Answer guidance: Include any special characters/punctuation.

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

## 300 Series Questions