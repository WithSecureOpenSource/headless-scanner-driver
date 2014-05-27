headless-scanner-driver
=======================

Python Burp Suite extension for non-interactive active scanning.
Burp and Burp Suite are trademarks of Portswigger, Ltd.

Usage
-----

Load this extension into Burp Extender using the GUI. You also need to
acquire the standalone Jython interpreter (version 2.7 or newer) and
tell Burp Suite where it is. After this, it will start an active scan
for all HTTP requests that are initiated through the proxy.

WARNING: The extension will indiscriminately start active scanning against
all URIs it sees, regardless of Burp Suite GUI Active Scanner setting.
To protect non-target sites, set a Target Scope and drop all requests not in suite
scope.

The extension will write JSON objects to stdout, one per line.

Run Burp Suite in headless mode using:

java -jar -Xmx1g -Djava.awt.headless=true -XX:MaxPermSize=1G burpsuite.jar

The extension intercepts two special kinds of HTTP requests; those to
ports 1111 and 1112.

If you think this sort of in-band signaling is odd, I agree. At the
time of writing, I just could not find a well-defined way of
communicating to an extension from outside Burp.

Your client can emit HTTP requests to port 1111 to get the extension
to emit its status. The status will be a JSON that is a list of pairs
of status information. There is one pair per a scanner instance
(typically per URL that the extension has seen). The status info pair
has the number of findings from that scanner instance, and the
completeness as a string. When all of the instances are finished, the
scan has finished.

Your client can emit a HTTP request to port 1112 which causes the
extension to dump all scanner findings and to cleanly exit.

For examples of how to use this from Python, see
https://github.com/F-Secure/mittn/blob/master/mittn/headlessscanner/

Bugs
----

Please report bugs to the GitHub project tracker or just send a patch
as a pull request.

Other queries can be sent via email to opensource@f-secure.com.
