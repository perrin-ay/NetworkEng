import pandas as pd
import numpy as np
import sys
import os
import sqlite3
import time
from pytz import timezone
import pytz
import datetime
from elasticsearch import Elasticsearch
import json
import os
from elasticsearch import helpers
import argparse

def epochtotzone(ep,tzo):


    tzn=timezone(tzo)
    t=datetime.datetime.utcfromtimestamp(ep).replace(tzinfo=pytz.utc)
    x= t.astimezone(tzn)
    return t.strftime("%Y-%m-%dT%H:%M:%S")

def dbpush(f,ftype,indx,tzone):
    
    jsonlist=[]
    mapping = {
    "mappings": {
        "properties": {
            "DateTime": {
                "type": "Date",
                "format": "yyyy-MM-dd'T'HH:mm:ss"
            }
        }
    }
}
    
    if 'security' in ftype:
        colls=['DateTime','TargetID','TargetType','TargetPort','TargetIP','TransID','TunnelID','VHostID','VDID','IsPassiveMode','Title','ParamName','ParamValue','Parameters','ParamType','ServerID','URI','Description','Geo']
        indexes=[indx]
    elif 'system' in ftype:
        colls=['DateTime','Title','Description']
        indexes=[indx]
    print 'f and tzone %s %s'%(f,tzone)    
    con = sqlite3.connect(f)
    con.text_factory = lambda b: b.decode(errors = 'ignore') # added to ignore utf-8 decode failure
    cursor = con.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    qu='SELECT * from %s'%'Events'
    df=pd.read_sql(qu,con)
    df['DateTime']=df['DateTime'].apply(epochtotzone,args=(tzone,))
    df=df[colls]
    if 'security' in ftype:
        df['TransID'] = df['TransID'].astype(str)
    jsonlist=df.to_dict("rows")

    es = Elasticsearch([{'host': '10.107.246.16', 'port': '9200'}])
    if 'security' in ftype:
        es.indices.delete(index=indx, ignore=[400, 404])
    if 'system' in ftype:
        es.indices.delete(index=indx, ignore=[400, 404])
    print es.cluster.health()
    
    for ind in indexes:
        es.indices.create(index=ind, ignore=400,body=mapping)
    helpers.bulk(es, jsonlist, index=indexes[0], request_timeout=200,ignore=[400, 404])

    



#tzone='Asia/Taipei'
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #optional arguments
    parser.add_argument("--security", type=str,help="Security db filename")
    parser.add_argument("--system", type=str,help="System db fileame")
    parser.add_argument("--timezone", type=str,help="Timezone of alteon or aw device")
    parser.add_argument("--security_indx", type=str,help="Security db elastic index")
    parser.add_argument("--system_indx", type=str,help="System db elastic index")

    args = parser.parse_args()
    if args.security:
        dbpush(args.security,'security',args.security_indx,args.timezone)
    if args.system:
        dbpush(args.system,'system',args.system_indx,args.timezone)
        

