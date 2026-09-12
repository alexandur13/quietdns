package main

import (
 "net"
 "strings"
 "time"
 "github.com/miekg/dns"
)

type resolver struct {store *Store;slots chan struct{}}
func (r *resolver) resolve(req *dns.Msg,transport string)(*dns.Msg,string,string) {
 reply:=new(dns.Msg);reply.SetReply(req);reply.RecursionAvailable=true
 if req.Opcode!=dns.OpcodeQuery||len(req.Question)!=1 {reply.Rcode=dns.RcodeFormatError;return reply,"error","Malformed query"}
 q:=req.Question[0]
 if q.Qclass!=dns.ClassINET||q.Qtype==dns.TypeAXFR||q.Qtype==dns.TypeIXFR {reply.Rcode=dns.RcodeRefused;return reply,"error","Unsupported query"}
 if canonical(q.Name)=="health.quietdns.internal"&&q.Qtype==dns.TypeTXT {
  reply.Answer=[]dns.RR{&dns.TXT{Hdr:dns.RR_Header{Name:q.Name,Rrtype:dns.TypeTXT,Class:dns.ClassINET,Ttl:0},Txt:[]string{"ok"}}};return reply,"allowed","Health check"
 }
 blocked,allowed:=r.store.policy(q.Name)
 if blocked {reply.Rcode=dns.RcodeNameError;return reply,"blocked","Domain rule"}
 for _,upstream:=range r.store.upstreams() {
  client:=&dns.Client{Net:transport,Timeout:2*time.Second}
  answer,_,err:=client.Exchange(req,upstream)
  if err==nil&&answer.Truncated&&transport=="udp" {client.Net="tcp";answer,_,err=client.Exchange(req,upstream)}
  if err!=nil||answer==nil||answer.Rcode==dns.RcodeServerFailure||answer.Rcode==dns.RcodeRefused {continue}
  if len(answer.Question)!=1||!strings.EqualFold(answer.Question[0].Name,q.Name)||answer.Question[0].Qtype!=q.Qtype||answer.Question[0].Qclass!=q.Qclass {continue}
  if !allowed {for _,rr:=range answer.Answer {if cname,ok:=rr.(*dns.CNAME);ok {if denied,_:=r.store.policy(cname.Target);denied {reply.Rcode=dns.RcodeNameError;return reply,"blocked","Blocked CNAME target"}}}}
  status:="allowed";reason:="Forwarded";if answer.Rcode==dns.RcodeNameError{status="notfound";reason="Upstream NXDOMAIN"}else if answer.Rcode!=dns.RcodeSuccess {status="error";reason=dns.RcodeToString[answer.Rcode]}
  return answer,status,reason
 }
 reply.Rcode=dns.RcodeServerFailure;return reply,"error","Upstreams unavailable"
}
func privateClient(address net.Addr)bool {host,_,err:=net.SplitHostPort(address.String());if err!=nil{return false};ip:=net.ParseIP(host);return ip!=nil&&(ip.IsLoopback()||ip.IsPrivate()||ip.IsLinkLocalUnicast())}
func (r *resolver) ServeDNS(w dns.ResponseWriter,req *dns.Msg) {
 if !privateClient(w.RemoteAddr()) {reply:=new(dns.Msg);reply.SetRcode(req,dns.RcodeRefused);_ = w.WriteMsg(reply);return}
 select {case r.slots<-struct{}{}:defer func(){<-r.slots}();default:reply:=new(dns.Msg);reply.SetRcode(req,dns.RcodeServerFailure);_ = w.WriteMsg(reply);return}
 started:=time.Now();transport:="udp";if _,ok:=w.RemoteAddr().(*net.TCPAddr);ok{transport="tcp"}
 answer,status,reason:=r.resolve(req,transport)
 if transport=="udp" {size:=uint16(512);if opt:=req.IsEdns0();opt!=nil&&opt.UDPSize()>size{size=opt.UDPSize()};if size>1232{size=1232};answer.Truncate(int(size))}
 _ = w.WriteMsg(answer)
 if len(req.Question)==1&&canonical(req.Question[0].Name)!="health.quietdns.internal" {
  host,_,_:=net.SplitHostPort(w.RemoteAddr().String())
  r.store.record(Query{Time:time.Now().UTC(),Domain:canonical(req.Question[0].Name),Type:dns.TypeToString[req.Question[0].Qtype],Client:host,Status:status,Reason:reason,Latency:float64(time.Since(started).Microseconds())/1000})
 }
}
