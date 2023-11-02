# Splunk BOTS v1 Recap

### Q101: What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

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


Using this information, we are not interested to know which `src_ip` has the highest hits to `192.168.250.70`, which may be indicative of web scanning and thus our threat actor. We can run the below SPL query and pipe in the top `src_ip` command, which will reveal `40.80.148.42` as the top count (substantially more than the others).

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