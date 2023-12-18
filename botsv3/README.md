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
![Q200](/splunk-bots/botsv3/images/Q200_1.png)


**Answer: bstoll, btun, splunk_access, web_admin**



### Q201: What field would you use to alert that AWS API activity has occurred without MFA?

We know that there is a field within the sourcetype `aws:cloudtrail` called `eventType` which contains a value named `AwsApiCall`. We can first run the below query and see if there are any interesting fields associated with the returned events.

```
index=botsv3 sourcetype=aws:cloudtrail eventType=AwsApiCall
```



![Q201_1](/splunk-bots/botsv3/images/Q201_1.png)

![Q201_2](/splunk-bots/botsv3/images/Q201_2.png)

When examining the fields, there is a field called `userIdentity.sessionContext.attributes.mfaAuthenticated` with the value of `false`. Based on the lengthy and descriptive field name with the value of false, it is most likely associated with events that occured without MFA.

**Answer: userIdentity.sessionContext.attributes.mfaAuthenticated**


### Q202: What is the processor number used on the web servers? Answer guidance: Include any special characters/punctuation.

The lab provided hint suggests using the sourcetype `hardware`.

We can simply first run the below query and see if any interesting fields or data is returned.

```
index=botsv3 sourcetype=hardware
```

![Q202_1](/splunk-bots/botsv3/images/Q202_1.png)

Right away, you can examine eiter in the event data or check the field `cpu_type` to see that the web servers use Intel Xeon CPU E5-2676, which the processor number is E5-2676.

**Answer: E5-2676**



## Q204: Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access?

For this question, it may be useful to refer to AWS documentation regarding S3 buckets and access control lists ("ACL") at https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html. From the documentation and other available resources, we know that the keywords putbucketacl or the command `put-bucket-acl` may be relevant and useful to incldue in our SPL query as it refers to a AWS S3 API call used to set or update the ACL permissions of a S3 bucket. Since we know Bud accidentally made a S3 bucket public, putbucketacl (or `put-bucket-acl`) will likely help us hone in on the event.

```
index=botsv3 sourcetype=aws:cloudtrail (putbucketacl OR "put-bucket-acl")
```

![204_1](/splunk-bots/botsv3/images/Q204_1.png)

We were able to return 2 events. We can either expand some of the interesting fields within the event data or sift through any interesting fields, such as `requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.xmlns:URI`, which will show that the bucket is accessible to all users.

![204_2](/splunk-bots/botsv3/images/Q204_2.png)

![204_3](/splunk-bots/botsv3/images/Q204_3.png)

This event corresponds to the Event ID of ab45689d-69cd-41e7-8705-5350402cf7ac.

**Answer: ab45689d-69cd-41e7-8705-5350402cf7ac**


## Q205: What is Bud's username?

We can modify the query from Q204 to simply add the command `table` against the field `userName`, which gives us the one unique value of bstoll - the 'b' likely stands for Bud and is likely Bud's username.

```
index=botsv3 sourcetype=aws:cloudtrail (putbucketacl OR "put-bucket-acl")
| table userName
```
![205_1](/splunk-bots/botsv3/images/Q205_1.png)


**Answer: bstoll**


## Q206: What is the name of the S3 bucket that was made publicly accessible?

Using the same query from Q204, there is a field called `requestParameters.bucketName` with the value of `frothlywebcode`.

**Answer: frothlywebcode**

## Q207: What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible? 

To view more specific logs about S3 buckets, we'll need to look into the sourcetype `aws:s3:accesslogs`. We know that bucket name is frothlywebcode. When uploading data or a resource to a server, we know that the HTTP method or operation is a PUT (and not GET), and the http status code is typically 200. With this information and examining the fields within the sourcetype `aws:s3:accsslogs`, we build the below query and output the field `request_uri` which will contain the file name.

```
index=botsv3 sourcetype=aws:s3:accesslogs bucket_name=frothlywebcode operation="REST.PUT.OBJECT" http_status=200
| table request_uri
```
![207_1](/splunk-bots/botsv3/images/Q207_1.png)

From our table results, it is most likely "OPEN_BUCKET_PLEASE_FIX.txt" based on the urgency and unusual file name.

**Answer: OPEN_BUCKET_PLEASE_FIX.txt**.




## 300 Series Questions