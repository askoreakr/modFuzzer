'''
Created on Apr 16, 2013

@author: Ali, samdory
'''
import socket
import sys
from types import *
import struct

HOST = '127.0.0.1'    # The remote host
PORT = 502            # The same port as used by the server
TANGO_DOWN = ''


def dumb_fuzzing(s):
  length1 = 0
  length2 = 6
  unitID = 1

  for transID1 in range(0,255):
    for transID2 in range(0,255):
      for protoID1 in range(0,255):
        for protoID2 in range(0,255):
#         for length1 in range(0,255):
#           for length2 in range(0,255):
#             for unitID in range(0,255):
                for functionCode in range(0,255):
                  for functionData1 in range(0,65535):
                    for functionData2 in range(0,65535):
                      TotalModbusPacket =  ""
                      TotalModbusPacket += struct.pack(">B", transID1)
                      TotalModbusPacket += struct.pack(">B", transID2)
                      TotalModbusPacket += struct.pack(">B", protoID1)
                      TotalModbusPacket += struct.pack(">B", protoID2)
                      TotalModbusPacket += struct.pack(">B", length1)
                      TotalModbusPacket += struct.pack(">B", length2)
                      TotalModbusPacket += struct.pack(">B", unitID)
                      TotalModbusPacket += struct.pack(">B", functionCode)
                      TotalModbusPacket += struct.pack(">H", functionData1)
                      TotalModbusPacket += struct.pack(">H", functionData2)
#                     TotalModbusPacket =  '%02x%02x%02x%02x%02x%02x%02x%02x%04x%04x' % (transID1, transID2, protoID1, protoID2, length1, length2, unitID, functionCode, functionData1, functionData2)
#                     print '         transID  protoID  length  uID  funcCode  funcData'
                      print 'Sent Msg : %02x %02x,  %02x %02x,  %02x %02x,   %02x,   %02x,    %04x, %04x' % (transID1, transID2, protoID1, protoID2, length1, length2, unitID, functionCode, functionData1, functionData2)
                      s.send(TotalModbusPacket)
#                     data = s.recv(1024)
#                     print 'Received :', repr(data)



if len(sys.argv) < 3:
    print "modbus fuzzer v0.1"
    print ""
    print "Usage: python modFuzzer.py [destination_IP] [-D]"
    print "                           [destination_IP] [-I packet]"
    print ""
    print "Commands:"
    print "Either long or short options are allowed."
    print "  --dumb   -D                Fuzzing in dumb way"
    print "  --input  -I packet         Fuzzing with given modbus packet"
    print ""
    print "Example:"
    print "python modFuzzer.py 127.0.0.1 -D"
    print "python modFuzzer.py 192.168.0.101 -I 0000000000060103000A0001"
    print ""
    exit(1)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error, msg:
    sys.stderr.write("[ERROR] %s\n" % msg[1])
    sys.exit(1)

HOST = sys.argv[1]
print 'Connecting to %s' % sys.argv[1]

try:
    sock.connect((HOST, PORT))
except socket.error, msg:
    sys.stderr.write("[ERROR] %s\n" % msg[1])
    sys.exit(2)

print 'Connected successfully'
argv2 = sys.argv[2]

if (argv2=='-D') or (argv2=='--dumb'):  # dumb fuzzing
    dumb_fuzzing(sock)
    sys.exit(1)

elif (argv2=='-I') or (argv2=='--input'):       # smart user input
    strInput = sys.argv[3]
    dataSend = ""
    shortInput = ""
    cnt = 1
    for chInput in strInput:
        shortInput += chInput
        if cnt%2 == 0:
            intInput = int(shortInput,16)
            dataSend += struct.pack(">B", intInput)
            shortInput = ""
        cnt += 1
    sock.send(dataSend)
    print 'sent: %s' % repr(dataSend)
    dataRecv = sock.recv(1024)
    print >>sys.stderr, 'received: %s' % repr(dataRecv)
    if dataRecv==TANGO_DOWN:
        print 'TANGO DOWN !!!'

sock.close()
sys.exit(0)
