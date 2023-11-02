# Splunk BOTS v1 Recap

### Q101
What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

First, we need to identify the IP address that belongs to our web server, which is likely what the threat group is scanning. We can run the below SPL query with the pipe command to return the destination IP address (`dest_ip`) with the highest hits, which is likely indicative of a web server.

`
index="botsv1" sourcetype="stream:http"
`
<br>
`
| top dest_ip
`

After running this SPL query, we see that the IP address with the most hits is `192.168.250.70`.

![ss1](./botsv1/images/ss1.png)

We can double check and confirm that this is in fact the IP address that belongs to `imreallynotbatman.com` by adding the IP address into the query, and then checking what data it is most commonly associated with in the `site` field.

`
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70"
`
<br>
`
| top site
`