# Splunk BOTS v2 Recap

This Splunk BOTS recap and walkthrough is based on the Version 2 (2017) event. You can download the botsv2 dataset from https://github.com/splunk/botsv2 and load into a Splunk instance, or you can sign up for an account at https://tryhackme.com and play along.


## Table of Contents

* 100 Series Questions

    * Q1: Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited?

    * Q2: Amber found the executive contact information and sent him an email. What image file displayed the executive's contact information? Answer example: /path/image.ext

    * Q3: What is the CEO's name? Provide the first and last name.

* 200 Series Questions
* 300 Series Questions
* 400 Series Questions



## 100 Series Questions

### Q1: Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited?

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


### Q2: Amber found the executive contact information and sent him an email. What image file displayed the executive's contact information? Answer example: /path/image.ext

Now that we know what the site is, we can run the below SPL query and take a closer look at the values for the field `url_path`.

```
index="botsv2" sourcetype="stream:http" src_ip="10.0.2.101" site="www.berkbeer.com"
```

![Q2_1](./images/Q2_1.png)

![Q2_2](./images/Q2_2.png)

When examining the values for `url_path`, we can keep in mind for any possible path names that reference the CEO or contact information. `/images/ceoberk.png` seems to be the most relevant path name that may suggest being related to the CEO and possibly containing contact information.

**Answer: /images/ceoberk.png**


### Q3: What is the CEO's name? Provide the first and last name.

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

If we try to view as raw data for this result, we can try to see if there's any content in the raw data that would provide the first/last name. We know it probably starts with an M so we can keep that in mind. Ctrl+F `berk`` or ctrl+F `mberk@berkbeer.com` and cycling through all the results is likely the best way to sift through the raw data to identify the first/last name within approximate location of the name berk or the email.

After sifting through the raw data, we've identified that the CEO's full name is Martin Berk.

![Q3_5](./images/Q3_5.png)

**Answer: Martin Berk**





## 200 Series Questions



## 300 Series Questions



## 400 Series Questions


