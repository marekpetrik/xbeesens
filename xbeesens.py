#!/usr/bin/python3
import configparser
import binascii
import serial
import operator
import logging
import argparse
import threading
import time
import json
from xbee.zigbee import ZigBee
from xbee.helpers.dispatch import Dispatch
import cherrypy


# TODO: Make sure that the lastvalues dictionary is synchronized
# maps node name to its last received value
lastvalues = {}
# A queue used to send xbee messages
xbeeque = None
# Maps a node name to the serial number
nametoserial = None

def h2b(hexcode):
    return bytes.fromhex(hexcode)

def b2h(bytecode):
    return binascii.hexlify(bytecode).decode(encoding='ascii')

def pintocommand(pname):
    return pname.upper().encode(encoding='ascii', errors='strict')

# Configuration values for the pins
pintovalue = {
    'off' : h2b('00'),
    'default' : h2b('01'),
    'analog' : h2b('02'),
    'digital' : h2b('03'),
    'output_lo' : h2b('04'),
    'output_hi' : h2b('05') }

pinlist = ['d0','d1','d2','d3','d4','d6','d7','p0','p1','p2']

# Main methods
def config_client(xbee,dispatch,masterconfig,nodeconfig):
    """
    Configures the sensor node
    
    Parameters
    ----------
    xbee : xbee object
    dispatch : xbbe dispatch
    masterconfig : dict
        Master configuration file
    nodeconfig : dict
        Node configuration file
    """

    resp = threading.Event()
    
    serialnumber = ''
    def response_handler(name,packet):
        nonlocal serialnumber
        if packet['frame_id'] == h2b('01'):
            assert len(serialnumber) == 0
            serialnumber += b2h(packet['parameter'])
        if packet['frame_id'] == h2b('02'):
            serialnumber += b2h(packet['parameter'])    
            resp.set()
            
        logging.debug(' Received packet : "%s"', str(packet).replace('\n',' '))
    
    dispatch.register(
        "at_response_handler", 
        response_handler,
        lambda packet: (packet['id'] == 'at_response')
    )

    # Read the id of the xbee and determine whether it already is in the configuration file
    resp.clear()
    xbee.at(frame_id=h2b('01'),command=b'SH')
    xbee.at(frame_id=h2b('02'),command=b'SL')
    if not resp.wait(1):
        logging.critical('No response from the xbee, make sure that it is in API mode.')
        raise ValueError('No xbee response.')    
    
    logging.info('Connected xbee with serial number "%s".', serialnumber)
    # Determine allowed node types
    logging.debug('Parsing node types from the main file')
    try:
        nodetypes = [nt for nt in masterconfig.keys() if nt != 'DEFAULT'] + ['MASTER']
        logging.debug('Loaded node types %s', nodetypes)
        networkid = masterconfig['DEFAULT']['networkid']    # assuming this was checked for existence and validity before
    except:
        logging.critical('Could not parse the main configuration file (default: xbeesens.cfg).')
        raise
    
    logging.debug('Parsing node configuration file.')
    try:
        if len(nodeconfig['DEFAULT']) > 0:
            logging.warning('Node configuration file must not contain any DEFAULT entries or a sensor named "DEFAULT". DEFAULT sensor will be ignored.')
        
        nodes = [(name,node) for name,node in nodeconfig.items() if name != 'DEFAULT' and node['serial'] == serialnumber]
        if len(nodes) > 1:
            logging.critical('Nodes with duplicate serial numbers in the configuration file.')
            raise ValueError('Nodes with duplicate serial numbers in the configuration file.')
        elif len(nodes) == 1:
            nodename = nodes[0][0]
            nodetype = nodes[0][1]['type']
            
            if nodetype not in nodetypes:
                logging.critical('Invalid type "%s" for node "%s" with serial number "%s". Allowed types are: %s.',nodetype,nodename,serialnumber,nodetypes)
                raise ValueError('Invalid node type.')
        else:
            logging.error('No node with serial number "{1}" defined in "{0}" (or the file does not exist). Please add the following configuration entry to the file e.g.:\n[CustomNodeName]\nserial = {1}\ntype = <type>\n# Allowed types: {2}'.format(config['DEFAULT']['nodefile'], serialnumber, nodetypes))
            return
            
    except Exception as e:
        logging.critical('Could not parse the node configuration file "%s".', config['DEFAULT']['nodefile'])
        raise e
    
    if nodetype == 'MASTER':
        logging.info('Configuring a master node.')
        
        # Set network id
        logging.debug('Setting network id.')
        xbee.at(frame_id=h2b('0A'),command=b'ID',parameter=h2b(networkid))
        
        # Auto connect to the network
        logging.debug('Setting network autoconnect.')
        xbee.at(frame_id=h2b('06'),command=b'VJ',parameter=h2b('01'))
    
    
    else: # Dealing with a SENSOR node
        logging.info('Configuring a sensor node.')
        # ---- PARSE pin information
        logging.debug('Parsing pin configuration.')
        nodetypeinfo = masterconfig[nodetype]
        try:
            pinsparsed = ((pinname.replace('pin_',''),value) for pinname,value in nodetypeinfo.items() if pinname.startswith('pin_') )
            
            pinconfig = []
            for pname,ptype in pinsparsed:
                if pname not in pinlist:
                    logging.warning('Unknown pin identifier "%s". Ignoring.',pname)
                    continue
                if ptype not in pintovalue:
                    logging.error('Unknown type "%s" for pin "%s". Ignoring.', ptype, pname)
                    continue
                pinconfig.append( (pname,pintovalue[ptype]) )
            
            logging.debug('Pin configuration: "%s".', pinconfig) 
        except:
            logging.critical('Invalid pin configuration for node type "%s".', nodeconfig)
            raise
        
        # --- START configuration
        logging.info('Configuring attached sensor "%s" to type "%s".', nodename, nodetype)
        
        # Set the parent to be the mesh master node
        logging.debug('Setting target node.')
        xbee.at(frame_id=h2b('08'),command=b'DL',parameter=h2b('00'))
        xbee.at(frame_id=h2b('09'),command=b'DH',parameter=h2b('00'))
        
        # Set network id
        logging.debug('Setting network id.')
        xbee.at(frame_id=h2b('0A'),command=b'ID',parameter=h2b(networkid))
        
        # Set pin information
        logging.debug('Writing pin information')
        for pname,ptype in pinconfig:
            command = pintocommand(pname)
            logging.debug('Sending AT command "%s" parameter "%s"',command,ptype)
            xbee.at(frame_id=h2b('04'),command=command,parameter=ptype)
    
        # Set sampling interval. It is 1 second initially to prevent long sleep - changed when bound
        logging.debug('Setting node sampling interval.')
        xbee.at(frame_id=h2b('05'),command=b'IR',parameter=h2b('03e8')) 
        
        # Auto connect to the network
        logging.debug('Setting network autoconnect.')
        xbee.at(frame_id=h2b('06'),command=b'VJ',parameter=h2b('01'))
    
    # Write configuration
    logging.debug('Writing node configuration.')
    xbee.at(frame_id=h2b('07'),command=b'WR',parameter=h2b('00'))
    
    print('Configured node {0} to type {1}.'.format(nodename,nodetype))

class XBeeMessage:
    """
    Message to be stored in the message queue to be sent to an xbee client
    """
    def __init__(self,type,longaddress,command,parameter):
        self.type = type
        self.longaddress = longaddress
        self.parameter = parameter
        self.command = command

class MainHandler(object):

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def get(self,node='all'):
        global lastvalues
        
        if node == 'all':
            return(lastvalues)
        elif node in lastvalues:
            return(lastvalues[node])
        else:
            return({'error':'Invalid node name.'})
            
    @cherrypy.expose
    @cherrypy.tools.json_out()        
    def set(set,node='None',pin='None',value='Node'):
        global lastvalues
        global xbeeque
        global nametoserial

        if node not in lastvalues:
            return {'error':'Invalid node name.'}
        if pin not in pinlist + ['d5']:
            return {'error':'Invalid pin name.'}
        if value not in ['0','1']:
            return {'error':'Invalid value'}
        
        valraw = h2b('04') if value == '0' else h2b('05')
        xbeeque.put(XBeeMessage('remote_at',h2b(nametoserial[node]),pintocommand(pin),valraw))
        return {'node':nametoserial[node], 'pin':pin,'value':value}

def listen(xbee,dispatch,masterconfig,nodeconfig):
    """
    Launches a service that communicates with the xbee sensors and a webserver interface
    """
    logging.info('Starting the listening sequence.')
    
    import queue
    global xbeeque
    xbeeque = queue.Queue()
    
    # TODO: make sure that the right master node is consistent with the configuration file
    
    # Parse the node types
    logging.debug('Parsing node types from the main file.')
    try:
        nodetypes = [nt for nt in masterconfig.keys() if nt != 'DEFAULT']
        # maps node type to interval in string hex form
        typetointerval = {}
        for nt in nodetypes:
            ni = masterconfig[nt]['sampleperiod']
            nih = hex(int(ni))[2:]
            if len(nih) > 4:
                logging.error('Invalid sampling period "%s" and its hex representation "%s" -- at most 4 hex digits.',ni,nih)
            if len(nih) < 4:
                nih = ('000' + nih)[-4:] 
            typetointerval[nt] = nih
            
        logging.debug('Loaded node types %s.', nodetypes)
        logging.debug('Loaded node intervals %s.', typetointerval)
    except:
        logging.critical('Could not parse the main configuration file (default: xbeesens.cfg).')
        raise
    
    # Load node configuration
    logging.debug('Parsing node configuration file.')
    try:
        if len(nodeconfig['DEFAULT']) > 0:
            logging.warning('Node configuration file must not contain any DEFAULT entries or a sensor named "DEFAULT". DEFAULT sensor will be ignored.')
            
        nodelist = [(name,node) for name,node in nodeconfig.items() if name != 'DEFAULT']    
            
        for name,node in nodelist:
            if node['type'] not in nodetypes and node['type'] != 'MASTER':
                logging.critical('Unknown node type: "%s". Terminating.', node['type'])
                raise ValueError('Unknown node type: "%s". Terminating.' % node['type'])
            
        serialtoname = {node['serial'] : name for name,node in nodelist}
        global nametoserial
        nametoserial = {name : node['serial'] for name,node in nodelist}
        nametotype = {name : node['type'] for name,node in nodelist}
    
    except Exception as e:
        logging.critical('Could not parse the node configuration file "%s".', config['DEFAULT']['nodefile'])
        raise e
    
    # Load pin and formula configuration for each nodes
    try:
        # pins marked for association (if none, then there is no entry)
        nametopins = {}
        # formulas for the node
        nametoformulas = {}
        for name,nodepars in nodelist:
            if nodepars['type'] == 'MASTER':
                continue
            
            pinsparsed = list((pinname.replace('pin_',''),value) \
                        for pinname,value in masterconfig[nametotype[name]].items() if pinname.startswith('pin_') )
            
            formulasparsed = list((forname.replace('formula_',''),value) \
                        for forname,value in masterconfig[nametotype[name]].items() if forname.startswith('formula_') )
            
            logging.debug('Parsed pin values: %s', pinsparsed)
            if len(pinsparsed) == 0:
                logging.error('No pins configured for node "%s".', name)
            
            pinconfig = []
            for pname,ptype in pinsparsed:
                if pname not in pinlist:
                    logging.warning('Unknown pin identifier "%s". Ignoring.',pname)
                    continue
                if ptype not in pintovalue:
                    logging.error('Unknown type "%s" for pin "%s". Ignoring.', ptype, pname)
                    continue
                pinconfig.append( (pname,pintovalue[ptype]) )
            
            logging.debug('Node %s pin configuration: "%s".', name,pinconfig) 
            
            nametopins[name] = pinconfig
            nametoformulas[name] = formulasparsed
            
    except:
        logging.critical('Invalid pin configuration for node type "%s".', nodeconfig)
        raise
    
    # Maps serial number addresses to short ones
    logging.debug('Initializing address map.')
    #TODO : make sure that all the code is thread safe (add semaphors)
    shortaddressmap = {}
    
    def onprocesspacket(longaddress, shortaddress,packet,nodename=None):
        """
        Processes general packet handling
        
        Returns
        -------
        out : bool
            True if successfull, False if the packet should be skipped
        """
        if nodename is None:
            hexlongaddress = b2h(longaddress)
            if hexlongaddress not in serialtoname:
                logging.warning('Unknown node with serial number "%s" connected. Ignoring.', hexlongaddress)
                return False
            nodename = serialtoname[hexlongaddress]
        
        #  First make sure that the short address is correct and registered
        if longaddress not in shortaddressmap:
            logging.info('Registered (%s,%s)' % (b2h(longaddress), b2h(shortaddress)))
            shortaddressmap[longaddress] = shortaddress
        elif shortaddressmap[longaddress] != shortaddress:
            logging.info('Re-registered (%s,%s)' % (b2h(longaddress), b2h(shortaddress)))
            shortaddressmap[longaddress] = shortaddress
        else:
            logging.debug('Correct short address in the dictionary (%s,%s)' % (b2h(longaddress), b2h(shortaddress)) )
        
        # reads the packet to determine whether the node is OK or needs to be updated
        # if yes then it turns off the association light  and sets the correct sampling interval
        if 'samples' in packet and len(packet['samples']) > 0:
            
            # Proceed only when this is a packet with samples
            samples = packet['samples'][0]
            
            if ('dio-5' not in samples) or (samples['dio-5'] is True):
                # if the sample is not present
                logging.info('Initilizing node "%s" (updating pin information).', nodename) 
                # Turn off the indicator light
                xbeeque.put(XBeeMessage('remote_at',longaddress,b'D5',h2b('04')),True,1)
                # Set the correct sampling time interval
                interval = h2b(typetointerval[nametotype[nodename]])
                logging.debug('Setting sampling interval to %s', interval)
                xbeeque.put(XBeeMessage('remote_at',longaddress,b'IR',interval),True,1)

                # Set pin information
                logging.debug('Writing pin information')
                
                for pname,ptype in nametopins[nodename]:
                    command = pname.upper().encode(encoding='ascii', errors='strict')
                    logging.debug('Sending AT command "%s" parameter "%s"',command,ptype)
                    xbeeque.put(XBeeMessage('remote_at',longaddress,command,ptype))
                    
        else:
            logging.warning('Received a sample packet with no samples: "%s"', str(packet))

        #logging.info('Initializing node "%s", short "%s"' % (b2h(longaddress),b2h(dest_addr)))
        #xbee.remote_at(dest_addr_long=longaddress,dest_addr=dest_addr,frame_id=h2b('ab'),command=b'D5',parameter=h2b('04'))
        #xbee.remote_at(dest_addr_long=longaddress,dest_addr=dest_addr,frame_id=h2b('ac'),command=b'IR',parameter=h2b('ea60'))
        
        return True

    # Create handlers for various packet types
    def status_handler(type, packet):
        logging.info('Status or remote_at_response update received: %s from %s' % (b2h(packet['status']),b2h(packet['source_addr_long'])))
        logging.debug("Status update received:", packet)

    dispatch.register(
        "status", 
        status_handler, 
        lambda packet: packet['id']=='status' or packet['id']=='remote_at_response'
    )
    
    dispatch.register(
        "other", 
        lambda name,packet : logging.debug('Other package received:', packet),
        lambda packet: packet['id']!='status' and packet['id']!='remote_at_response' and packet['id']!='rx_io_data_long_addr'
    )
    
    # TODO: Make sure that the lastvalues dictionary is synchronized
    # maps node name to its last received value
    global lastvalues
    lastvalues = {name : None for name,nt in nodelist if nt['type'] != 'MASTER'}
    
    def io_sample_handler(type, packet):
        """
        Handles a sample from a node.
        
        Parameters
        ----------
        type : string
            Type of the packet
        packet : object
            An xbee packet
        """
        logging.debug('Starting sample hadler.')
        longaddress = packet['source_addr_long'] 
        shortaddress = packet['source_addr']
        
        # convert the address to a hexadecimal
        hexlongaddress = b2h(longaddress)
        if hexlongaddress not in serialtoname:
            logging.warning('Unknown node with serial number "%s" connected. Ignoring.', longaddress)
            return
        # name of the node
        nodename = serialtoname[hexlongaddress]
        
        if not onprocesspacket(longaddress,shortaddress,packet,nodename=nodename):
            return

        samples = packet['samples']
        if len(samples) != 1:
            logging.error('Something is wrong with the packet. There must be exactly one entry for "samples". Packet: "%s". Ignoring.', str(packet).replace('\n',' '))
        samples = samples[0]
        
        samples['timestamp'] = time.time()
        lastvalues[nodename] = samples
        logging.debug('Received a new sample for node "%s" with "%s".', nodename, samples)
        
        # Compute formulas
        formulas = nametoformulas[nodename]
        if len(formulas) > 0:
            samples_replaced = {n.replace('-','_'):v for n,v in samples.items()}
            for formname,formvalue in formulas:
                try:
                    exec('y=' + formvalue,samples_replaced)
                    if 'y' in samples_replaced:
                        samples[formname] = samples_replaced['y']
                    else:
                        samples[formname] = '#N/A'
                        logging.warning('Formula "%s" with value "%s" with packet "%s" did not set value to variable y.', formname, formvalue, str(packet))
                except Exception as e:
                    logging.error('Error computing formula "%s" with value "%s" with packet "%s": %s', formname, formvalue,  str(packet), str(e))
                    samples[formname] = '#ERR'

        logging.debug('Updating a new sample for node "%s" with "%s" after processing formulas.', nodename, samples)                    
                    
        
    dispatch.register(
        "io_data", 
        io_sample_handler,
        lambda packet: packet['id']=='rx_io_data_long_addr'
    )

    # run the message dispatch in a separate thread
    def message_dispatch():
        # Dispatch messages from the xbee queue
        logging.info('Staring message loop.')
        global xbeeque
        while True:
            try:
                message = xbeeque.get()
                if message.type == 'remote_at':
                    if message.longaddress in shortaddressmap:
                        shortaddress = shortaddressmap[message.longaddress]
                        logging.debug('Sending remote_at message "%s" with params "%s"', message.command, message.parameter)
                        xbee.remote_at(dest_addr_long=message.longaddress,dest_addr=shortaddress,\
                            frame_id=h2b('ab'),command=message.command,parameter=message.parameter)
                    else:
                        logging.warning('Short address not found - using long address; could be inefficient. Sending remote_at message "%s" with params "%s"', message.command, message.parameter)
                        xbee.remote_at(dest_addr_long=message.longaddress,\
                            frame_id=h2b('ab'),command=message.command,parameter=message.parameter)
                else:
                    logging.error('Message type not understood: "%s".', message.type)
            except KeyboardInterrupt:
                logging.warning('Caught keyboard interrupt. Exiting.')
                break
    thread = threading.Thread(target = message_dispatch)
    thread.start()


    # Starting web server
    if 'port' in masterconfig['DEFAULT']:
        portnumber = int(masterconfig['DEFAULT']['port'])
    else:
        logging.warning('No port number specified in the config file (DEFAULT/port), using 8888.')
        portnumber = 8888
        
    logging.info('Starting web server on port %s.' % portnumber)
    cherrypy.config.update({'server.socket_port': portnumber}) 
    cherrypy.quickstart(MainHandler())

if __name__ == '__main__':
    
    # make an exception when running interactively in iep
    # must manually create the args object
    if '__iep__' not in dir():
        parser = argparse.ArgumentParser(description='Configure xbee nodes and create an http gateway')
        parser.add_argument('command', choices=['configure','listen'],
                help='Command to run. "client"/"server" will configure the connected xbee, "listen" will launch a deamon that monitors and saves the received massages.') 
                
        parser.add_argument('--config',default='xbeesens.cfg', help='Configuration file.')
        parser.add_argument('--port',default='/dev/ttyUSB0', help='Port to which to communicate')
        parser.add_argument('--rate',default=9600,help='Communication rate', type=int)
        parser.add_argument('-v','--verbose',action='count',help='Increase logging verbosity, use -vvv for maximal verbosity.')

        args = parser.parse_args()
    else:
        if 'args' not in dir():
            class X:
                pass
 
            args = X()
            args.config = 'xbeesens.cfg'
            args.verbose = 3 
            args.port = '/dev/ttyUSB0'
            args.rate = 9600
            args.command = 'listen'
    
    # Determine the right verbosity
    if args.verbose == 0 or args.verbose == None:
        level = logging.ERROR
    elif args.verbose == 1:
        level = logging.WARNING
    elif args.verbose == 2:
        level = logging.INFO
    elif args.verbose == 3:
        level = logging.DEBUG
    else:
        raise ValueError('Invalid log level: %s' % args.verbose)
        
    logging.basicConfig(format='%(asctime)s: %(levelname)s:  %(message)s',level=level)
    
    logging.info('Reading main configuration file "%s".',args.config)
    config = configparser.ConfigParser()
    config.read(args.config)
    
    if 'networkid' not in config['DEFAULT']:
        raise ValueError('Missing "networkid" in DEFAULT group of the configuration file.')
    
    try:
        hexnet = h2b(config['DEFAULT']['networkid'])
        logging.debug('Byte representation of network id "%s".', hexnet)
        if len(hexnet) != 2:
            raise ValueError('network id is not 2 bytes')
    except:
        logging.critical('Failed parsing networkid. It is "%s", but must be a 4-digit hexadecimal.', config['DEFAULT']['networkid'])
        raise
    
    if 'nodefile' not in config['DEFAULT']:
        raise ValueError('Missing "nodefile" in DEFAULT group of the configuration file.')
    nodefilename = config['DEFAULT']['nodefile']    
    
    logging.info('Reading nodes configuration "%s"', nodefilename)
    nodeconfig = configparser.ConfigParser()
    try:
        nodeconfig.read(nodefilename)
    except:
        logging.critical('Could not read the node configuration file "%s".', nodefilename)
        raise
    
    # Open serial port
    with serial.Serial(args.port,args.rate) as ser:
        # Create an xbee ZigBee communication object
        dispatch = Dispatch(ser)
        logging.debug('Creating xbee object.')
        xbee = ZigBee(ser,callback=dispatch.dispatch)

        try:
            if args.command == 'listen':
                listen(xbee,dispatch,config,nodeconfig)
            elif args.command == 'configure':
                config_client(xbee,dispatch,config,nodeconfig)
            else:
                logging.critical('Unknown command "%s", terminating.',args.command)
        finally:
            # halt() must be called before closing the serial port in order to ensure proper thread shutdown
            logging.info('Halting xbee.')
            xbee.halt()
            ser.close()
    logging.info('Closed serial port.')

    #with open('example.cfg', 'w') as configfile:
    #    config.write(configfile)
