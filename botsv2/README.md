# Splunk BOTS v2 Recap

This Splunk BOTS recap and walkthrough is based on the Version 2 (2017) event. You can download the botsv2 dataset from https://github.com/splunk/botsv2 and load into a Splunk instance, or you can sign up for an account at https://tryhackme.com and play along.


## Table of Contents

* 100 Series Questions

    * Q100-1: Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited?

    * Q100-2: Amber found the executive contact information and sent him an email. What image file displayed the executive's contact information? Answer example: /path/image.ext

    * Q100-3: What is the CEO's name? Provide the first and last name.

    * Q100-4: What is the CEO's email address?

    * Q100-5: After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?

    * Q100-6: What is the name of the file attachment that Amber sent to a contact at the competitor?

    * Q100-7: What is Amber's personal email address?



* 200 Series Questions
    * Q200-1: What version of TOR Browser did Amber install to obfuscate her web browsing? Answer guidance: Numeric with one or more delimiter.

    * Q200-2: What is the public IPv4 address of the server running www.brewertalk.com?

    * Q200-3: Provide the IP address of the system used to run a web vulnerability scan against www.brewertalk.com.

    * Q200-4: The IP address from Q#2 is also being used by a likely different piece of software to attack a URI path. What is the URI path? Answer guidance: Include the leading forward slash in your answer. Do not include the query string or other parts of the URI. Answer example: /phpinfo.php

    * Q200-5: What SQL function is being abused on the URI path from the previous question?

    * Q200-6: What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of an XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.

    * Q200-7: What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of an XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.




* 300 Series Questions
* 400 Series Questions



## 100 Series Questions

### Q100-1: Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited?

To see a list of websites Amber visited, we'd need to narrow in on Amber's IP address within the sourcetype `stream:http`. We can identify Amber's IP address by running the SPL command below with Amber's name to see if there are results associated with a particular IP address.

```
index="botsv2" sourcetype="pan:traffic" amber
```

![Q1_1](./images/Q1_1.png)


When we examine the `src_ip` field, we notice that there's several hits for one specific value (and no other values observed). Based on this, this is likely the IP address that belongs to Amber.

![Q1_2](./images/Q1_2.png)

We can now run the below SPL query to put the values of the `site` field in a table. It's important to consider that the same site may have been visited multiple times, thus there are multiple hits/counts. We can omit duplicate values by applying the `dedup` command to the field `site` as well.

```
index="botsv2" sourcetype="stream:http" src_ip:"10.0.2.101"
| table site
| dedup site
```

We are then presented with a table of 107 different values. We know that Amber's company is in the beer/brewing industry, so we could manually sift through the results until we identify a domain name that may be associated to this industry. After manually sifting through the data, we identified the value of `www.berkbeer.com`. Based on the domain name and its possible association to the beer/brewing industry, this is likely the competitor's website.

**Answer: www.berkbeer.com**

![Q1_3](./images/Q1_3.png)


### Q100-2: Amber found the executive contact information and sent him an email. What image file displayed the executive's contact information? Answer example: /path/image.ext

Now that we know what the site is, we can run the below SPL query and take a closer look at the values for the field `url_path`.

```
index="botsv2" sourcetype="stream:http" src_ip="10.0.2.101" site="www.berkbeer.com"
```

![Q2_1](./images/Q2_1.png)

![Q2_2](./images/Q2_2.png)

When examining the values for `url_path`, we can keep in mind for any possible path names that reference the CEO or contact information. `/images/ceoberk.png` seems to be the most relevant path name that may suggest being related to the CEO and possibly containing contact information.

**Answer: /images/ceoberk.png**


### Q100-3: What is the CEO's name? Provide the first and last name.

We know that "ceoberk" might hint that berk is part of the name and will keep this in mind. We could determine first and last name information from email traffic/data derived from sourcetype `stream:smtp`. But before anything we'll need to find Amber's email. We can use the below SPL query and see if there are any interesting field/values that might give a clue as to what Amber's email is.

```
index="botsv2" sourcetype="stream:smtp" amber
```

![Q3_1](./images/Q3_1.png)

Examining the results show us that the fields `sender`, `sender_alias`, and `sender_email` is of interest to us, and we've identified the email assocaited with Amber (`aturing@froth.ly`).

![Q3_2](./images/Q3_2.png)

With this information, we can revise our SPL query to now include Amber's email and toss in the keyword "berk" and see if anything comes up.

```
index="botsv2" sourcetype="stream:smtp" aturing@froth.ly berk
```

![Q3_3](./images/Q3_3.png)

Examining the single result we get back, we can identify the CEO's email, but it doesn't seem to provide the first/last name. At least we know the first name likely starts with an M based on the email naming convention.

![Q3_4](./images/Q3_4.png)

If we try to view as raw data for this result, we can try to see if there's any content in the raw data that would provide the first/last name. We know it probably starts with an M so we can keep that in mind. Ctrl+F `berk` or ctrl+F `mberk@berkbeer.com` and cycling through all the results is likely the best way to sift through the raw data to identify the first/last name within approximate location of the name berk or the email.

After sifting through the raw data, we've identified that the CEO's full name is Martin Berk.

![Q3_5](./images/Q3_5.png)

**Answer: Martin Berk**


### Q100-4: What is the CEO's email address?

See solution to Q3.

**Answer: mberk@berkbeer[.]com** 

### Q100-5: After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?

From prior solutions, we learned that Berk Beer is the competitor company and that their email domain is `@berkbeer.com`. Using this information, we can build the below SPL query to search through the sourcetype `stream:smtp` for any events that match Amber's email with the email domain of `@berkbeer`. We know one of the events should be Amber's email with the CEO.

```
index="botsv2" sourcetype="stream:smtp" aturing@froth.ly berk
```

![Q5_1](./images/Q5_1.png)

When examining the events, we can see that there is the field `receiver_email` with the value of `hbernhard@berkbeer.com`, which appears to be the employee's email.

![Q5_2](./images/Q5_2.png)

**Answer: hbernhard@berkbeer[.]com**



### Q100-6: After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?

See solution to Q5.

When examining the event data associated to `hbernhard@berkbeer.com`, we see that there is the field `attach_filename` with the value of `Saccharomyces_cerevisiae_patent.docx`, which appears to be the name of the file attachment.

**Answer: Saccharomyces_cerevisiae_patent.docx**



### Q100-7: What is Amber's personal email address?

When reading the raw data or viewing the values for the field `content_body`, we see what appears to be an encoded message. Interestingly enough, if we expand and view the values for the field `content_transfer_encoding`, it has a value of `base64`. Based on this information, we can copy the value from `content_body` and paste it into https://gchq.github.io/CyberChef and use the **From Base64** recipe.

![Q7_1](./images/Q7_1.png)

![Q7_2](./images/Q7_2.png)

After pasting in the encoded string into the Input box, we can see under the Output box the email conversation thread in cleartext where Amber's personal email is `ambersthebest@yeastiebeastie.com`. Yikes, looks like there's a potential insider threat/risk situation on our hands.

**Answer: ambersthebest@yeastiebeastie[.]com**



## 200 Series Questions

### Q200-1: What version of TOR Browser did Amber install to obfuscate her web browsing? Answer guidance: Numeric with one or more delimiter.

We can build the generic SPL query below to check for events matching both `tor` (the browser application we're interested in) and `amber` (Amber's host machine likely has directories that is inclusive of her name). There are over 300 events that match our query. 

```
index="botsv2" tor amber
```

![Q200-1_1](./images/Q200-1_1.png)

If we examine the Interesting Fields section, we see that there is a field called `Image`. Typically, images may contain information of a specific version/firmware of a particular application. If we expand the field `Image`, we can see that there is a value that references a TOR install as 7.0.4, which is likely the version of the TOR browser Amber installed.


![Q200-1_2](./images/Q200-1_2.png)

**Answer: 7.0.4**


### Q2: What is the public IPv4 address of the server running www.brewertalk.com?

Technically, you could run a `dig` command against the domain www.brewertalk.com to query it's DNS information. However, there is the chance that the public IP address has since changed or has been updated.


Instead, we can likely find this information within the sourcetype `stream:http` and build a SPL query that looks for events related to www.brewertalk.com and filters for destination ports equal to 80 or 443 (as expected for a web server). Additionally, we'll add in the splunk command `stats count by dest_ip` to see if there is one particular IP address that stands out with a substantial amount of events.

```
index="botsv2" sourcetype="stream:http" www.brewertalk.com (dest_port=80 OR dest_port=443)
| stats count by dest_ip
```

![Q200-2_1](./images/Q200-2_1.png)

Right away, we see that 172.31.4.249 has a really high count number, but this address is in the private address space so we know this cannot be the answer. The only other address is a public IP address, which is likely the public address of the server running www.brewertalk.com.

**Answer: 52.42.208.228**



## 300 Series Questions



## 400 Series Questions



