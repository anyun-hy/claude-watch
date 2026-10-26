import importlib.util, pathlib, tempfile, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('coffee',pathlib.Path(__file__).parents[1]/'Resources/netcoffee_client.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class ClientTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='coffee-client-');self.addCleanup(self.temp.cleanup)
  self.cache=patch.object(c,'_cache_root',return_value=pathlib.Path(self.temp.name));self.cache.start();self.addCleanup(self.cache.stop)
 def test_endpoint_allowlist(self):
  self.assertEqual(c.endpoint('lookup','1.1.1.1'),'https://ip.net.coffee/api/ip/lookup/1.1.1.1')
  self.assertIn('/geoip/2606:4700:4700::1111',c.endpoint('geoip','2606:4700:4700::1111'))
 def test_private_and_injection_rejected(self):
  for ip in ['127.0.0.1','198.18.0.2','192.168.1.1','fe80::1','::1','1.1.1.1/../../x','1.1.1.1?x=1','2606:4700:4700::1111%en0']:
   with self.assertRaises(ValueError):c.endpoint('geoip',ip)
 def test_no_scanning_api(self):
  with self.assertRaises(ValueError):c.endpoint('portscan','1.1.1.1')
 def test_token_restricted(self):
  with self.assertRaises(ValueError):c.endpoint('dns','../etc')
 def test_http_error_is_not_complete(self):
  with patch.object(c.subprocess,'Popen') as p:
   p.return_value.communicate.return_value=(b'{"trust_score":99}\n429',b'');p.return_value.returncode=0
   r=c.request('lookup','1.1.1.1');self.assertEqual(r['status'],'error');self.assertEqual(r['httpStatus'],429)
 def test_429_keeps_retry_after_without_retaining_headers(self):
  with patch.object(c.subprocess,'Popen') as p:
   p.return_value.communicate.return_value=(b'{}\n429',b'Retry-After: 1800\r\nSet-Cookie: private-token\r\n');p.return_value.returncode=0
   with patch.object(c.Path,'read_bytes',return_value=b'Retry-After: 1800\r\nSet-Cookie: private-token\r\n'):
    r=c.request('lookup','9.9.9.9');self.assertEqual(r['retry_after'],1800);self.assertNotIn('private-token',repr(r))
 def test_temporary_header_file_is_private_and_deleted_for_success_and_429(self):
  for body,headers,status in ((b'{"ip":"1.1.1.1"}\n200',b'Set-Cookie: private-token\r\n','complete'),(b'{}\n429',b'Retry-After: 1800\r\nSet-Cookie: private-token\r\n','error')):
   with self.subTest(status=status):
    paths=[];modes=[]
    class Task:
     returncode=0
     def communicate(_,timeout=None):
      header=pathlib.Path(paths[-1]);modes.append(header.stat().st_mode&0o777);header.write_bytes(headers);return body,b''
     def terminate(_):pass
     def kill(_):pass
    def popen(args,**kwargs):
     paths.append(args[args.index('--dump-header')+1]);return Task()
    with patch.object(c.subprocess,'Popen',side_effect=popen):
     r=c._request_uncached('lookup','1.1.1.1')
    self.assertEqual(r['status'],status);self.assertEqual(modes,[0o600]);self.assertFalse(pathlib.Path(paths[0]).exists());self.assertNotIn('private-token',repr(r))
    if status=='error':self.assertEqual(r['retry_after'],1800)
 def test_ip_mismatch(self):
  with patch.object(c.subprocess,'Popen') as p:
   p.return_value.communicate.return_value=(b'{"ip":"8.8.8.8","trust_score":99}\n200',b'');p.return_value.returncode=0
   self.assertEqual(c.request('lookup','1.1.1.1')['status'],'error')
 def test_transport_fixed_proxy_no_redirects_or_user_curl_config(self):
  with patch.object(c.subprocess,'Popen') as p:
   p.return_value.communicate.return_value=(b'{"ip":"1.1.1.1","trust_score":41}\n200',b'');p.return_value.returncode=0
   c.request('lookup','1.1.1.1');args=p.call_args.args[0]
   self.assertEqual(args[1],'--disable');self.assertEqual(args[args.index('--proxy')+1],'http://127.0.0.1:7890');self.assertNotIn('--location',args)
 def test_dns_empty_retained_not_fabricated(self):
  with patch.object(c.subprocess,'Popen') as p:
   p.return_value.communicate.return_value=(b'{"dns_servers":[]}\n200',b'');p.return_value.returncode=0
   self.assertEqual(c.request('dns','a'*24)['data'],{'dns_servers':[]})
 def test_html_invalid_json(self):
  with patch.object(c.subprocess,'Popen') as p:
   p.return_value.communicate.return_value=(b'<html>blocked</html>\n200',b'');p.return_value.returncode=0
   self.assertEqual(c.request('geoip','1.1.1.1')['status'],'error')
if __name__=='__main__':unittest.main()
