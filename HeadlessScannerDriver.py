"""
Copyright (c) 2013-2014 F-Secure
See LICENSE for details

This file is intended to be run as a Burp Suite Professional extension.
Burp and Burp Suite are trademarks of Postswigger, Ltd.
"""

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IHttpRequestResponse
from burp import IHttpService
from burp import IProxyListener
from burp import IScannerListener
from burp import IHttpListener
from burp import IScanQueueItem
from burp import IInterceptedProxyMessage
from java.io import PrintWriter
import json
import re
import copy


class BurpExtender(IBurpExtender, IScannerListener, IProxyListener, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        self._scanlist = []  # Holds scan items (Burp data structures)
        self._scantarget = []  # Holds list of URLs added to scan
        # set our extension name
        callbacks.setExtensionName("Headless Scanner Driver")
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        # register ourselves as listeners
        callbacks.registerScannerListener(self)
        callbacks.registerProxyListener(self)
        self._stdout.println(json.dumps({"running": 1}))  # Indicate we're up
        self._stdout.flush()
        return

    def processProxyMessage(self, messageIsRequest, message):
        # This method is called for every externally triggered request.
        callbacks = self._callbacks  # As stored in registerExtenderCallbacks
        message.setInterceptAction(
            IInterceptedProxyMessage.ACTION_DONT_INTERCEPT)  # Inform Burp not to intercept the message.

        if messageIsRequest == 1:  # Booleans are integers

            # Obtain message target & content
            requestresponse = message.getMessageInfo()
            request = requestresponse.getRequest()  # returns array.array
            target = requestresponse.getHttpService()
            host = target.getHost()
            port = target.getPort()
            protocol = target.getProtocol()

            # Interpret in-band signaling from the test driver
            # (any request to ports 1111, 1112 will get intercepted as
            # an instruction to this extension)
            if port == 1111:  # Show scan status
                message.setInterceptAction(
                    IInterceptedProxyMessage.ACTION_DROP)  # Was a control message, do not process further
                statuses = []
                for scaninstance in self._scanlist:
                    statuses.append(scaninstance.getStatus())
                # This output may block due to output buffers being filled.
                # When running this extension, something should be reading
                # stdout.
                self._stdout.println(json.dumps(statuses))
                self._stdout.flush()
                return

            if port == 1112:  # Dump results and quit
                message.setInterceptAction(
                    IInterceptedProxyMessage.ACTION_DROP)  # Was a control message, do not process further
                scanissues = self.get_issues()
                # This output may block due to output buffers being filled.
                # When running this extension, something should be reading
                # stdout.
                self._stdout.println(json.dumps(scanissues, encoding="utf-8"))
                self._stdout.flush()
                callbacks.exitSuite(0)  # Exit cleanly
                return

            if port == 1113:  # Dump results but don't quit
                message.setInterceptAction(
                    IInterceptedProxyMessage.ACTION_DROP)  # Was a control message, do not process further
                scanissues = self.get_issues()
                #clear the scanlist to avoid getting previous issues from future scans
                self._scanlist = []
                # This output may block due to output buffers being filled.
                # When running this extension, something should be reading
                # stdout.
                self._stdout.println(json.dumps(scanissues, encoding="utf-8"))
                self._stdout.flush()
                return
            # Duplicate scan rejection

            urlpath = re.search('^\w+ (.+) HTTP', request.tostring())
            if urlpath is not None:
                url = protocol + "://" + host + urlpath.group(1)
                if self._scantarget.count(url) == 0:  # Not already scanned?
                    self._scantarget.append(url)
                    # Start an active scan on the message
                    https = 0
                    if protocol == "https":
                        https = 1
                    scaninstance = callbacks.doActiveScan(host,
                                                          port,
                                                          https,
                                                          request)
                    self._scanlist.append(scaninstance)
        return

        def get_issues():
            scanissues = []
            # Collect issues. We have a list of scans that contain
            # scan findings. Extract these and dump in a JSON.
            for scaninstance in self._scanlist:
                for scanissue in scaninstance.getIssues():
                    issue = {}
                    issue['url'] = scanissue.getUrl().toString()
                    issue['severity'] = scanissue.getSeverity()
                    issue['issuetype'] = scanissue.getIssueType()
                    issue['issuename'] = scanissue.getIssueName()
                    issue['issuedetail'] = scanissue.getIssueDetail()
                    issue['confidence'] = scanissue.getConfidence()
                    issue['host'] = scanissue.getHttpService().getHost()
                    issue['port'] = scanissue.getHttpService().getPort()
                    issue['protocol'] = scanissue.getHttpService().getProtocol()
                    messages = []
                    for httpmessage in scanissue.getHttpMessages():
                        request = httpmessage.getRequest().tostring()
                        request = request.encode('utf-8')
                        response = httpmessage.getResponse().tostring()
                        response = response.encode('utf-8')
                        messages.append((request,
                                         response))
                    issue['messages'] = messages
                    scanissues.append(copy.copy(issue))
            return scanissues
