import urllib, urllib2, sys
from optparse import OptionParser
class RblCheck:

	def is_valid_ip(self,ip_addr):
		'''Checking valid ip address'''
		is_int =  ''.join(ip_addr.split('.'))
		if is_int.isdigit():
			temp = ip_addr.split('.')
			if ((int(temp[0]) < 223) and (int(temp[1]) <= 255) and (int(temp[2]) <= 255) and (int(temp[3]) <= 255)):
				return True
			else: return False
		else: return False
	
	def reverseIP(self,ip_addr):
		rev_ip_addr=''
		for i in reversed(ip_addr.split('.')):
			rev_ip_addr = rev_ip_addr +'.'+i
		rev_ip_addr = rev_ip_addr.strip('.')
		return rev_ip_addr
	
	def rbl_check(self,rev_ip,ip_addr):
		rbl_list = {
			".sbl.spamhaus.org": "http://www.spamhaus.org/lookup/",
			".pbl.spamhaus.org": "http://www.spamhaus.org/lookup/",
			"xbl.spamhaus.org": "http://www.spamhaus.org/lookup/",
			".zen.spamhaus.org": "http://www.spamhaus.org/lookup/",
			".dnsbl.sorbs.net":  "http://www.sorbs.net/delisting/overview.shtml",
			".dnsbl.ahbl.org":  "http://www.ahbl.org/lktool",
			".bl.spamcop.net":  "http://www.spamcop.net/fom-serve/cache/76.html",
			".ips.backscatterer.org": "http://www.backscatterer.org/?target=contact",
			".cbl.abuseat.org": "http://cbl.abuseat.org/lookup.cgi",
			".b.barracudacentral.org": "http://www.barracudacentral.org/rbl/removal-request",
			".cidr.bl.mcafee.com": "http://www.trustedsource.org/",
			".bl.mailspike.net": "http://mailspike.org/iplookup.html",
			".dnsbl-0.uceprotect.net": "http://www.uceprotect.net/en/index.php?m=7"
		}
		for key, value in rbl_list.iteritems():
			rbl_lookup = 'http://' + rev_ip + key
			try:
				req = urllib2.urlopen(rbl_lookup)
				req_code = req.getcode()
				if req_code == 200:
					print '[+] {0} found in {1}, request removal at {2}'.format(ip_addr, key, value)
					req_location = urllib2.urlopen('http://api.hostip.info/get_html.php?ip={0}&position=true').read()
					print req_lcation
			except:
				continue



parser = OptionParser()
parser.add_option('-i','--input', dest = 'ip', help = 'Give IP to check against RBL')
parser.add_option('-f','--file', dest = 'file', help = 'Takes file containing IPs one/line as input')
(options, args) = parser.parse_args()

if len(sys.argv[1:]) == 0:
    print "no argument given!"
    parser.print_help()

rbl_chk = RblCheck()
if options.ip and options.file: 
	print "Only one option at a time"
	exit()

elif options.file:
	f = open(options.file,'r')
	print 'file'
	for line in f:
		line = line.strip('\n')
		if rbl_chk.is_valid_ip(line):
			rev = rbl_chk.reverseIP(line)
			print rbl_chk.rbl_check(rev, line)
	f.close()
		
elif options.ip: 
       	if rbl_chk.is_valid_ip(options.ip):
		rev = rbl_chk.reverseIP(options.ip)
		print rbl_chk.rbl_check(rev, options.ip)

else: exit()	
