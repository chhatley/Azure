## Notice/Warning
* This solution is designed for a lab environment and test purposes. Use it at your own risk.


## What is Deployed
This will deploy Active Directory with couple domain controllers and optional application servers. 
There will be nothing else deployed into this AD - no users, groups, GPOs. Clean new ADDS for testing of whatever.

After deployment is done you will need to go into FrontEndNSG and modify inbound rule to allow RDP traffic from IP of your device.
Then you will be able to RDP into JumpBox. From there you will be able to connect to DCs and App Servers. Simple!

It will deploy the following topology:


## Notes: 
	• You can chose OS version for DCs (2016 or 2012R2). Two DCs are installed as part of this lab
	• You can chose if you need to install App Servers (clean servers joined to domain) and OS version for each. Up to 4 servers can be deployed.
	• You can decide to have different account name for admin - do not use admin, administrator etc - those will not be accepted on Azure VMs and your deployment will probably bomb
	• You can decide to have your own custom password. The default would be in the following format: "Subscription#YOURSCUBSCRIPTIONID#",  something like this Subscription#xgxgxg-dhdh-wtyu-9876-550fjfjfjfkf
	• You can modify Source Client IP address to your IP address (or *) at the start or later in frontend NSG. This will allow you to RDP into JumpBox. Or use VM JIT via ASC, if you have it enabled.
	• VMs will be scheduled to auto shutdown daily at 9PM MST. Change it to what you need.
	• VMs are Standard A2. Not very powerful. You can change it to bigger VM post deployment. 