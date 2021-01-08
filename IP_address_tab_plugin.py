from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IExtensionStateListener

from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;

from threading import Lock
import socket
import json
import datetime

#load dictionary containing {hostname : IP addresses} {key : value} pairs
with open('DNS_file.txt') as file:
    dns_database = json.load(file)

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IExtensionStateListener, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Nikki's first plug-in")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        # register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "IP Address Logger"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return
        
        # create a new log entry with the message details
        hostname=str(messageInfo.getHost())

        if hostname.startswith('www.'):
            short_hostname = hostname.replace('www.','')
        else:
            short_hostname=hostname
       
        # check if hostname is already in the dictionary
        if short_hostname in dns_database:
            IP_addresses=dns_database[short_hostname]

        # if not already in the dictionary, retrieve all corresponding IP addresses and add to dictionary         
        else:
            try:
                full_address_list=socket.getaddrinfo(short_hostname, 0, socket.AF_INET, socket.SOCK_STREAM)
                IP_addresses=[]
                for address in range(len(full_address_list)):
                    IP_addresses.append(full_address_list[address][-1][0])
                dns_database[short_hostname]=IP_addresses
            except:
                IP_addresses='error'


        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), short_hostname, IP_addresses, datetime.datetime.now()))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 4


    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "Host"
        if columnIndex == 2:
            return "IP"
        if columnIndex == 3:
            return "Time stamp"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._host
        if columnIndex == 2:
            return logEntry._IP
        if columnIndex == 3:
            return logEntry._timestamp
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    #
    # implement IExtensionStateListener
    #

    def extensionUnloaded(self):
        #save dictionary to file upon unloading the extension
        with open('DNS_file.txt', 'w') as file:  
            file.write(json.dumps(dns_database))
        return

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, host, IP, timestamp):
        self._tool = tool
        self._requestResponse = requestResponse
        self._host = host
        self._IP = IP
        self._timestamp = timestamp


