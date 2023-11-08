<!--
*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock.  
 *
-->
## Gateway Communication Example Usage
* [Kerberos Authentication Example](https://github.com/ForgeRock/gateway-communication-node/blob/main/sample/Readme.md#kerberos-authentication)

## Kerberos Authentication Example
### Prerequisites
1. Kerberos authentication must be enabled in Active Directory.
2. Install Identity Gateway and ensure the Java environment truststore is setup to trust server certificates.
3. Ensure the Identity Gateway and the Active Directory servers can reach one another.
4. Synchronize the time between the Identity Gateway and the Active Directory server.
5. Create krb5.conf in the Java environment /lib/security/ directory.
6. Issue the following command on the Active Directory server assuming **demoig.server.frdpcloud.org** is the fully qualified domain name of the Identity Gateway Server and **igsa** is the service account samaccountname: 
      >setspn -s HTTP/demoig.server.frdpcloud.org igsa
7. Follow the [Gateway Communication node](https://backstage.forgerock.com/docs/idcloud/latest/release-notes/rapid-channel/auth-node-gateway-comm.html) setup.
8. Replace the AuthenticateLocalUser groovy script with the sample Kerberos script
