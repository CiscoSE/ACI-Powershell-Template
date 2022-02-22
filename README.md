This is a collection of simple powershell examples demonstrating ACI access from powershell using the invoke-WebRequest cmdlet


**aci-access-template.ps1**

This basic powershell example provided provides a framework for accessing the Cisco API via Powershell. The example performs the following functions:

* Obtains a cookie from the APIC through the XML API
* Provides a framework to perform POST and GET requests through the API

All API calls to the APIC are completed in the getData function. Differences in the invoke-WebRequest cmdlet require different methods of ensuring self signed certificates function without error. Because no certificate checking is being done, it is important to ensure you direct your APIC calls to the right server. 

This example is intended as a framework and doesn't produce much output from the APIC. If you want to see the calls made to the APIC and the resulting token, use the -verbose switch. This will show post data, including the user password passed when requesting the cookie. 

**aci-list-switches.ps1**

Intended as the simplest example of requesting data and returning it to the screen, this example lists all of the switches in the fabric. 

**aci-list-interface-stats.ps1**
Provides more advanced examples by list interfaces with options for different error reports. 
