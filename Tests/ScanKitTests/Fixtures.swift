import Foundation

/// Output -oX ridotto ma realistico di nmap 7.9x con tre host.
enum Fixtures {
    static let sampleXML = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" args="nmap -T4 -sV --script ssl-cert -oX - 10.0.1.0/24" start="1762700000" version="7.95" xmloutputversion="1.05">
    <host><status state="up" reason="arp-response"/>
      <address addr="10.0.1.1" addrtype="ipv4"/>
      <address addr="BC:24:11:00:00:01" addrtype="mac" vendor="Proxmox Server Solutions"/>
      <hostnames><hostname name="router.lan" type="PTR"/></hostnames>
      <ports>
        <port protocol="tcp" portid="23"><state state="open" reason="syn-ack"/><service name="telnet" product="BusyBox telnetd"/></port>
        <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="lighttpd"/>
          <script id="http-title" output="Router Admin"/></port>
        <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="lighttpd" tunnel="ssl"/>
          <script id="ssl-cert" output="Subject: commonName=router.lan&#xa;Issuer: commonName=router.lan&#xa;Not valid before: 2020-01-01T00:00:00&#xa;Not valid after:  2022-01-01T00:00:00"/>
          <script id="ssl-enum-ciphers" output="&#xa;  TLSv1.0: &#xa;    ciphers: &#xa;  TLSv1.2: &#xa;    ciphers: &#xa;  least strength: C"/></port>
        <port protocol="tcp" portid="8080"><state state="closed" reason="reset"/><service name="http-proxy"/></port>
      </ports>
      <os><osmatch name="Linux 4.15 - 5.19" accuracy="95"/><osmatch name="Linux 3.2" accuracy="88"/></os>
      <times srtt="1250" rttvar="500" to="100000"/>
    </host>
    <host><status state="up" reason="arp-response"/>
      <address addr="10.0.1.20" addrtype="ipv4"/>
      <ports>
        <port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/><service name="ftp" product="vsftpd" version="3.0.3"/>
          <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></port>
        <port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds"/></port>
        <port protocol="tcp" portid="6379"><state state="open" reason="syn-ack"/><service name="redis" product="Redis key-value store"/></port>
      </ports>
      <hostscript>
        <script id="smb-protocols" output="&#xa;  dialects: &#xa;    NT LM 0.12 (SMBv1) [dangerous, but default]&#xa;    2:1:0"/>
        <script id="smb2-security-mode" output="&#xa;  3:1:1: &#xa;    Message signing enabled but not required"/>
      </hostscript>
    </host>
    <host><status state="up" reason="syn-ack"/>
      <address addr="10.0.1.9" addrtype="ipv4"/>
      <ports>
        <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0"/></port>
        <port protocol="tcp" portid="5900"><state state="open" reason="syn-ack"/><service name="vnc"/>
          <script id="vnc-info" output="&#xa;  Protocol version: 3.8&#xa;  Security types: &#xa;    None (1)"/></port>
      </ports>
    </host>
    <host><status state="down" reason="no-response"/><address addr="10.0.1.200" addrtype="ipv4"/></host>
    <runstats><finished time="1762700120" elapsed="120"/><hosts up="3" down="1" total="4"/></runstats>
    </nmaprun>
    """
}
