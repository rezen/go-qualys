package qualys

var vulnInfoSample string = `
<VULN_INFO_LIST>
  <VULN_INFO>
      <QID id="qid_377999">377999</QID>
      <TYPE>Vuln</TYPE>
      <SSL>false</SSL>
      <RESULT><![CDATA[Vulnerable git version detected:
  git version 2.17.1]]></RESULT>
      <FIRST_FOUND>2021-01-20T08:17:16Z</FIRST_FOUND>
      <LAST_FOUND>2021-01-24T15:12:14Z</LAST_FOUND>
      <TIMES_FOUND>19</TIMES_FOUND>
      <VULN_STATUS>Active</VULN_STATUS>
      <QDS>60</QDS>
  </VULN_INFO>
</VULN_INFO_LIST>
`

var vulnDetailsSample string = `
<GLOSSARY>
  <VULN_DETAILS_LIST>
    <VULN_DETAILS id="qid_20316">
      <QID id="qid_20316">20316</QID>
      <TITLE><![CDATA[Oracle MySQL January 2021 Critical Patch Update (CPUJAN2021)]]></TITLE>
      <SEVERITY>3</SEVERITY>
      <CATEGORY>Database</CATEGORY>
      <THREAT><![CDATA[This Critical Patch Update contains 37 new security patches for Oracle MySQL. <P>

      Affected Versions:<BR>
      MySQL Server, versions 5.7.40 and prior, 8.0.31 and prior.<P>

      QID Detection Logic (Unauthenticated):<BR>
      This QID detects vulnerable versions of MySQL via the banner exposed by the service.<P>

      QID Detection Logic (Authenticated):<BR>
      This QID detects vulnerable versions of MySQL <P>]]></THREAT>
      <IMPACT><![CDATA[Successful exploitation could allow an attacker to affect the confidentiality, integrity, and availability of data on the target system.<BR>]]></IMPACT>
      <SOLUTION><![CDATA[Refer to vendor advisory <A HREF="https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL" TARGET="_blank">Oracle MySQL January 2021 </A>.<BR>
      <P>Patch:<BR>
      Following are links for downloading patches to fix the vulnerabilities:
      <P> <A HREF="https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL" TARGET="_blank">CPUJAN2021</A>]]></SOLUTION>
      <PCI_FLAG>1</PCI_FLAG>
      <LAST_UPDATE>2021-01-18T04:03:04Z</LAST_UPDATE>
      <VENDOR_REFERENCE_LIST>
        <VENDOR_REFERENCE>
        <ID><![CDATA[MySQL CPUJAN2021]]></ID>
        <URL><![CDATA[https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL]]></URL>
        </VENDOR_REFERENCE>
      </VENDOR_REFERENCE_LIST>
      <CVE_ID_LIST>
        <CVE_ID>
        <ID><![CDATA[CVE-2021-21866]]></ID>
        <URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21866]]></URL>
        </CVE_ID>
        <CVE_ID>
        <ID><![CDATA[CVE-2021-21872]]></ID>
        <URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21872]]></URL>
        </CVE_ID>
      </CVE_ID_LIST>
      </VULN_DETAILS>
  </VULN_DETAILS_LIST>
</GLOSSARY>

`

var hostSample string = `
<HOST_LIST>
  <HOST>
    <IP>172.27.9.27</IP>
    <TRACKING_METHOD>IP</TRACKING_METHOD>
    <ASSET_TAGS>
      <ASSET_TAG><![CDATA[Ice Cream]]></ASSET_TAG>
      <ASSET_TAG><![CDATA[Everything]]></ASSET_TAG>
      <ASSET_TAG><![CDATA[Passive Sensor]]></ASSET_TAG>
      <ASSET_TAG><![CDATA[sample-private]]></ASSET_TAG>
    </ASSET_TAGS>
    <HOST_ID><![CDATA[185725099]]></HOST_ID>
    <ARS>67</ARS>
    <ACS>4</ACS>
    <ASSET_GROUPS>
      <ASSET_GROUP_TITLE><![CDATA[sample-private]]></ASSET_GROUP_TITLE>
    </ASSET_GROUPS>
    <VULN_INFO_LIST>
      <VULN_INFO>
      <QID id="qid_38773">38773</QID>
      <TYPE>Practice</TYPE>
      <SSL>false</SSL>
      <RESULT><![CDATA[Vulnerable SSH-2.0-OpenSSH_8.0 detected on port 22 over TCP.]]></RESULT>
      <FIRST_FOUND>2020-05-26T21:18:31Z</FIRST_FOUND>
      <LAST_FOUND>2021-01-19T22:58:45Z</LAST_FOUND>
      <TIMES_FOUND>57</TIMES_FOUND>
      <VULN_STATUS>Active</VULN_STATUS>
      <QDS>42</QDS>
      </VULN_INFO>
    </VULN_INFO_LIST>
  </HOST>
</HOST_LIST>
`
