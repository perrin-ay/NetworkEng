import pandas as pd
import json
import sys
import os, os.path
import subprocess
import re
import time
from elasticsearch import Elasticsearch
from elasticsearch import helpers
import argparse
import registryfordash

class pcapobj(object):
    
    def __init__(self,folder='',filename=''):
        self.dir=folder
        self.file=filename
        self.results={'filename':[]}
    def tsharkcmd(self, cmd=['tshark -n -r']):
        self.tcmd=cmd
    def readcap(self,keyname='placeholder',results=True, export=[]):
        self.results[keyname]=[]
        self.start=self.dir
        if self.start:
            try:
                os.walk(self.start).next()
            except StopIteration:
                print 'Given start is not a directory. For file searches only use filename'
                sys.exit(0) 
        
            for (dirname, dirs, files) in os.walk(self.start):

                for c,f in enumerate(files):
                    thefile=os.path.join(dirname,f)
                    if len(self.tcmd)>1:
                        tcmd=self.tcmd[0]+' '+thefile+' '+' '.join(self.tcmd[1:])
                    else:
                        tcmd=self.tcmd[0]+' '+thefile 


                    out=os.popen(tcmd)
                    if results:
                        self.results[keyname].append(out.read())
                        self.results['filename'].append(thefile)
                
        elif self.file:
            if len(self.tcmd)>1:
                tcmd=self.tcmd[0]+' '+self.file+' '+self.tcmd[1:]
            else:
                tcmd=self.tcmd[0]+' '+self.file

            out=os.popem(tcmd)
            if results:
                self.results[keyname].append(out.read())
                self.results['filename'].append(self.file)
    
    def exportglobfields(self,etype='ip_tcp'):
        
        initfields=['frame.time_epoch','frame.protocols','frame.number','frame.len','frame.cap_len','eth.dst','eth.src','vlan.etype','vlan.id','eth.type','ip.version','ip.hdr_len','ip.len','ip.id','ip.flags','ip.frag_offset','ip.ttl','ip.proto','ip.src','ip.dst','udp.srcport','udp.dstport','tcp.srcport','tcp.dstport','tcp.seq','tcp.ack','tcp.hdr_len','tcp.flags','tcp.window_size_value','tcp.window_size','tcp.options.mss_val','tcp.options.wscale.shift','ssl.record.content_type','ssl.record.version','ssl.record.length','ssl.handshake.type','ssl.handshake.length','ssl.handshake.version','ssl.handshake.extensions_server_name','ssl.handshake.ciphersuite','http.request.method','http.request.uri','http.request.version','http.host','http.response.code','http.content_length_header','http.content_encoding','http.transfer_encoding','http.content_type']
        
        if etype=='ip_tcp':
            return [ '-e '+i for i in initfields if 'ip.' in i or 'eth.' in i or 'vlan.' in i or 'frame.time_epoch' in i or 'tcp.' in i or 'frame.len' in i or 'http.content_length_header' in i ]
        elif etype=='ip_udp':
            return [ '-e '+i for i in initfields if 'ip.' in i or 'eth.' in i or 'vlan.' in i or 'frame.time_epoch' in i or 'udp.' in i or 'frame.len' in i or 'http.content_length_header' in i]
        elif etype=='http':
            return [ '-e '+i for i in initfields if 'ip.' in i or 'frame.time_epoch' in i or 'tcp.' in i or 'http.' in i or 'frame.len' in i]
        elif etype=='tls':
            return [ '-e '+i for i in initfields if 'ip.' in i or 'frame.time_epoch' in i or 'frame.len' in i or 'tcp.' in i or 'ssl.' in i or 'http.' in i]
        else:
            return [ '-e '+i for i in initfields]
            
                
    def exportcap(self,export=[]):
        self.start=self.dir
        self.jsonfilenames=[]
        if self.start:
            try:
                os.walk(self.start).next()
            except StopIteration:
                print 'Given start is not a directory. select filename mode'
                sys.exit(0)
            for (dirname, dirs, files) in os.walk(self.start):

                for c,f in enumerate(files):
                    thefile=os.path.join(dirname,f)
                    if len(self.tcmd)>1:
                        tcmd=self.tcmd[0]+' '+thefile+' '+' '.join(self.tcmd[1:]) + ' > '+os.path.join(dirname,export[c])
                    else:
                        tcmd=self.tcmd[0]+' '+thefile + ' > '+os.path.join(dirname,export[c])
                    self.jsonfilenames.append(os.path.join(dirname,export[c]))    
                    os.popen(tcmd)
        elif self.file:
            if len(self.tcmd)>1:

                tcmd=self.tcmd[0]+' '+self.file+' '+' '.join(self.tcmd[1:]) + ' > '+export[0]
            else:
                tcmd=self.tcmd[0]+' '+self.file + ' > '+export[0]
            self.jsonfilenames.append(export[0])    
            os.popen(tcmd)
            
    def filescount(self,filetype=".pcap"):
        if self.dir:
            return len([name for name in os.listdir(self.dir) if os.path.isfile(os.path.join(self.dir, name)) and filetype in os.path.join(self.dir, name)])
        elif self.file:
            return 1
    
    def fileslist(self,filetype=".json"):
        if self.dir:
            return [os.path.join(self.dir, name) for name in os.listdir(self.dir) if os.path.isfile(os.path.join(self.dir, name)) and filetype in os.path.join(self.dir, name)]
        elif self.file:
            return self.file
    
    def _capsinfo_to_dict(self,lsdata):
        results2={'filename':[],'Data bit rate':[],'bitrate metric':[],'Avg packet size':[],'Avg packet rate':[],'packet rate metric':[]}
        for i in lsdata:
            for f in i.split('\n'):
                if f.startswith('Data bit rate'):
                    results2['Data bit rate'].append((re.findall(r"\d+", f)[0]))
                    results2['bitrate metric'].append(f.split(' ')[-1])
                if f.startswith('Average packet rate'):
                    results2['Avg packet rate'].append((re.findall(r"\d+", f)[0]))
                    results2['packet rate metric'].append(f.split(' ')[-1])
                if f.startswith("File name:"):
                    results2['filename'].append(f.split(' ')[-1])
                if f.startswith("Average packet size:"):
                    results2['Avg packet size'].append((re.findall(r"\d+", f)[0]))

        return  results2
    
def conto_ls(ls):
    res = ls.strip("']['").strip("'").split(', ')
    for c,i in enumerate(res):
        res[c]=i.strip("'")

    return res

    
        
    
def valupdates(ls,col):


    try:
        if col=='ssl_handshake_ciphersuite':
            if ls=="0" or ls=='':
                return ls
            elif int(ls) >0:
                return registryfordash.ciphers[ls]
        
        elif col =='ssl_handshake_type':
            if ls=="0":
                return ls
            if '[' in ls:
                lss=conto_ls(ls)
                for c,l in enumerate(lss):
                    lss[c]=registryfordash.recordtype[l.strip("u'")]
                return str(lss)
            else:
                return  registryfordash.recordtype[ls]
            
        elif col=='ssl_record_content_type':
            if ls=="0":
                return ls
            if '[' in ls:
                lss=conto_ls(ls)
                for c,l in enumerate(lss):
                    lss[c]=registryfordash.handshaketype[l.strip("u'")]
                return str(lss)
            else:
                return  registryfordash.handshaketype[ls]
            
        elif col =='ssl_record_version' or col =='ssl_handshake_version' :
            if ls=="0":
                return ls
            if '[' in ls:
                lss=conto_ls(ls)
                for c,l in enumerate(lss):
                    lss[c]=registryfordash.tlsvers[str(int(l.strip("u'"),16))]
                return str(lss)
            else:
                return  registryfordash.tlsvers[str(int(ls,16))]
            
        elif col=='eth_type':
            if ls=="0":
                return ls
            return  registryfordash.ethtype[str(int(ls,16))]
        
        elif col=='ip_proto':
            if ls=="0":
                return ls
            return  registryfordash.ipproto[str(ls)]
    
    except Exception:
        return ls
    
    
def replacelist2(ls):
    if type(ls) is list:
        if len(ls) > 1:
            return ''
        else: 
            return ls[0]

    else:
        return ls
def replacelist(ls):
    if type(ls) is list:
        if len(ls) > 1:
            return str(ls)
        else: 
            return ls[0]

    else:
        return ls

def makedf(df):
    
    df=df.fillna(0)
    
    bl=['ip_hdr_len', 'ip_len', 'ip_ttl', 'tcp_dstport','tcp_hdr_len', 'tcp_srcport', 'tcp_window_size','frame_len','http_content_length_header','frame_time_epoch','tcp_window_size_value','tcp_options_mss_val']

    sl=['ssl_record_content_type', 'ssl_record_version', 'ssl_handshake_type', 'ssl_handshake_length', 'ssl_handshake_version', 'ssl_handshake_extensions_server_name', 'ssl_handshake_ciphersuite', 'http_request_method', 'http_request_uri', 'http_request_version', 'http_host', 'http_response_code', 'http_content_encoding', 'http_transfer_encoding', 'http_content_type','ssl_record_length']
    
    allfields=['frame.time_epoch','frame.protocols','frame.number','frame.len','frame.cap_len','eth.dst','eth.src','vlan.etype','vlan.id','eth.type','ip.version','ip.hdr_len','ip.len','ip.id','ip.flags','ip.frag_offset','ip.ttl','ip.proto','ip.src','ip.dst','udp.srcport','udp.dstport','tcp.srcport','tcp.dstport','tcp.seq','tcp.ack','tcp.hdr_len','tcp.flags','tcp.window_size_value','tcp.window_size','tcp.options.mss_val','tcp.options.wscale.shift','ssl.record.content_type','ssl.record.version','ssl.record.length','ssl.handshake.type','ssl.handshake.length','ssl.handshake.version','ssl.handshake.extensions_server_name','ssl.handshake.ciphersuite','http.request.method','http.request.uri','http.request.version','http.host','http.response.code','http.content_length_header','http.content_encoding','http.transfer_encoding','http.content_type']

    for m in df.columns.tolist():
        if m=='ssl_handshake_ciphersuite':
            df[m]=df[m].apply(replacelist2)

        else:    
            df[m]=df[m].apply(replacelist)

        if m in sl:
            df[m]=df[m].astype("string")

        if m in bl:
            
            if m=='frame_time_epoch':
                df[m]=df[m].astype(float).astype(int)

            else:
                df[m]=df[m].astype(int)


    regiscols={'ssl_handshake_ciphersuite','ssl_handshake_type','ssl_record_content_type','ssl_record_version','ssl_handshake_version','eth_type','ip_proto'}

    regiscols=list(set(regiscols) & set(df.columns.tolist()))
    
    for col in regiscols:
        df[col]=df[col].apply(valupdates,args=(col,))

    jsonlist=df.to_dict("rows")
    del df
    return jsonlist


    
    
def pushtoes(filels,idxname):
    # filesls needs to be a list of filenames
    es = Elasticsearch([{'host': '10.107.246.16', 'port': '9200'}])
    es.indices.delete(index=idxname, ignore=[400, 404])
    indexes=[idxname]
    
    for ind in indexes:
        es.indices.create(index=ind, ignore=400)
        

    for i in filels:
        lss=[]
        jsonlist=[]
        emp=''
        
        with open (i) as fd:
            jsonbuf=fd.read()
        lm=jsonbuf.split("\n")
        
        for c,x in enumerate(lm):
            if c==0:
                pass
            elif c%2==0:
                pass
            else:
                lss.append(x)
        sz=len(lss)
        lm=None
        del lm
        
        lll='"layers" : {'
        lss =[i[i.find(lll)+len(lll)-1:] for i in lss]
        emp='\n'.join(lss)
        emp=emp.replace("}}","}")
        lss=None
        del lss
        
        for reader in pd.read_json(emp,lines=True,chunksize=100000):
            jsonlist=makedf(reader)
            helpers.bulk(es, jsonlist, index=idxname, request_timeout=200,ignore=[400, 404])
            del jsonlist


        
       
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #optional arguments
    parser.add_argument("--pcapfile", type=str,help="pcap filename")
    parser.add_argument("--pcapjsonfile", type=str,help="pcap json fileame. If createjsonfile is true this name will be used to create json file")
    parser.add_argument("--createjsonfile", action="store_true",help="create json file same name as pcap file")
    parser.add_argument("--capindex", type=str,help="ES idx name")
    parser.add_argument("--etype", type=str,help="fields to export when creating json file")
    parser.add_argument("--filter", type=str,help="tshark filter for pcap file. has default value if not provided")
    args = parser.parse_args()
    
    
    createjson=False
    if args.createjsonfile:
        createjson=True
# "tshark -Y 'tcp' -n "    
    if createjson:
        p=pcapobj(filename=args.pcapfile)
        if args.filter=='':
            args.filter="tshark -Y 'tcp' -n "
        ccmd=args.filter+ ' '.join(p.exportglobfields(etype=args.etype))+ " -r"
        p.tsharkcmd(cmd=[ccmd, "-T ek"])
        exportname=[args.pcapjsonfile]
        p.exportcap(export=exportname)
        pushtoes(exportname,args.capindex)
    
    else:
        exportname=[args.pcapjsonfile]
        pushtoes(exportname,args.capindex)


