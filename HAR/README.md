# HARreplay

Traffic replay of browser activity from HAR file using pandas for data processing and requests for traffic generation

---

**Usage**

hh=HarParse('/home/ftp/har/1/172.16.66.48.har')
hh.replay_har(replacedip={'172.16.66.48':'10.107.129.174'})

To explore the HTTP data in the HAR file:

df=hh.parse_to_df(responsebody=True)

