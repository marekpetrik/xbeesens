#!/usr/bin/python
from http import client
from urllib import parse
import logging
import json
import time
import threading
import configparser

configuration = 'dataupload.cfg'

config = configparser.ConfigParser()
config.read(configuration)
fields = ['field1','field2','field3','field4','field5','field6','field7','field8']

nodes = set(config.keys()) - {'MASTER','DEFAULT'}

headers = {"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"}     
url = '/get'
counter = 0

def updatenodes():
    while True:
        try:
            # update node information
            params = parse.urlencode({})
            conn = client.HTTPConnection(config['MASTER']['address'])
            conn.request('GET', url, params, headers)
            response = conn.getresponse()
            
            if response.status == 200:
                data = response.read()
                data = data.decode()
                data = json.loads(data)
                logging.info('Successfuly retrieved node data.')
                
                for n in nodes:
                    ni = config[n]
                    
                    if n not in data:
                        continue
                    
                    params = {'key':ni['writekey']}
                    # build query
                    for f in fields:
                        if f not in ni:
                            continue
                        if ni[f] not in data[n]:
                            continue
                        params[f] = data[n][ni[f]]
                        
                    params = parse.urlencode(params)
                    conn = client.HTTPConnection(config['MASTER']['thingspeakadd'])
                    conn.request('POST','/update',params,headers)
                    response = conn.getresponse()
                
                    if response.status != 200:
                        logging.error('Node %s upload failed, status: %s, reason: %s', n, response.status, response.reason)
                    else:
                        logging.info('Node %s upload succeeded, status: %s, reason: %s', n, response.status, response.reason)
            
            else:
                logging.error('Error retrieving node data "%s", skipping upload.', response.reason)
        
        except Exception as e:
            logging.critical('Node exception', e)
        
        time.sleep(float(config['MASTER']['nodetime']))
        
def updateweather():
    while True:
        try:
            # update weather information
            conn = client.HTTPConnection('api.wunderground.com')
            conn.request('GET','/api/078e1aedd14fa471/conditions/q/NY/Croton_on_Hudson.json')
            response = conn.getresponse()
            
            if response.status == 200:
                data = json.loads(response.read().decode())
                params = parse.urlencode({'key' : config['MASTER']['weatherkey'], \
                        'field1' : data['current_observation']['temp_c'], \
                        'field2' : data['current_observation']['relative_humidity'],\
                        'field3' : data['current_observation']['wind_kph'],\
                        'field4' : data['current_observation']['wind_gust_kph']})
                        
                conn = client.HTTPConnection(config['MASTER']['thingspeakadd'])
                conn.request('POST','/update',params,headers)
                response = conn.getresponse()
            
                if response.status != 200:
                    logging.error('Weather upload failed, status: %s, reason: %s', response.status, response.reason)
                else:
                    logging.info('Weather upload succeeded, status: %s, reason: %s', response.status, response.reason)
                
            
            else:
                logging.error('Error retrieving weather data "%s", skipping upload.', response.reason)
        
        except Exception as e:
            logging.critical('Weather exception', e)
            
        time.sleep(float(config['MASTER']['weathertime']))

if __name__ == '__main__':      
    logging.basicConfig(format='%(asctime)s: %(levelname)s:  %(message)s',level=logging.INFO)
  
    threading.Thread(target = updatenodes, daemon=False).start()        
    threading.Thread(target = updateweather,daemon=False).start()
