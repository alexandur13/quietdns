package main

import (
 "context"
 "fmt"
 "net"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/miekg/dns"
)

func testStore(t *testing.T)*Store{t.Helper();s,err:=newStore(t.TempDir());if err!=nil{t.Fatal(err)};return s}
func TestDomainPolicy(t *testing.T){s:=testStore(t);err:=s.change(func(v *Settings)error{v.Rules=[]Rule{{"ads.test","block"},{"safe.ads.test","allow"}};return nil});if err!=nil{t.Fatal(err)}
 for name,want:=range map[string]bool{"ads.test.":true,"SUB.ADS.TEST.":true,"notads.test.":false,"safe.ads.test.":false,"child.safe.ads.test.":false}{got,_:=s.policy(name);if got!=want{t.Errorf("%s: got %v, want %v",name,got,want)}}
 if err:=s.change(func(v *Settings)error{v.PausedUntil=time.Now().Add(time.Minute);return nil});err!=nil{t.Fatal(err)};if got,_:=s.policy("ads.test");got{t.Fatal("pause ignored")}
 if err:=s.change(func(v *Settings)error{v.PausedUntil=time.Now().Add(-time.Minute);return nil});err!=nil{t.Fatal(err)};if got,_:=s.policy("ads.test");!got{t.Fatal("pause did not expire")}
}
func TestListParsing(t *testing.T){list,err:=parseList("# comment\n0.0.0.0 ads.test tracker.test\nEXAMPLE.TEST.\n127.0.0.1 localhost\n");if err!=nil||len(list)!=3{t.Fatalf("unexpected parse: %v %v",list,err)}
 for _,line:=range []string{"||ads.test^","https://ads.test/path","<html>error.page</html>"}{if _,err:=parseList(line);err==nil{t.Fatalf("accepted invalid list %q",line)}}
}
func TestSettingsPersistence(t *testing.T){s:=testStore(t);if err:=s.change(func(v *Settings)error{v.Name="Test network";v.Rules=[]Rule{{"saved.test","block"}};return nil});err!=nil{t.Fatal(err)};again,err:=newStore(s.dir);if err!=nil{t.Fatal(err)};if again.snapshotSettings().Name!="Test network"{t.Fatal("name not persisted")};if got,_:=again.policy("saved.test");!got{t.Fatal("rule not persisted")}
 if err:=s.change(func(v *Settings)error{v.Name="";return nil});err==nil{t.Fatal("invalid change accepted")};if s.snapshotSettings().Name!="Test network"{t.Fatal("failed transaction changed state")}
}
func TestHistoryRetention(t *testing.T){s:=testStore(t);for i:=0;i<maxQueries+10;i++{s.record(Query{Time:time.Now().UTC(),Domain:"ads.test",Status:"blocked",Latency:2})};if len(s.history.Queries)!=maxQueries{t.Fatal("history not bounded")};if s.overview()["total"].(int)!=maxQueries+10{t.Fatal("aggregate lost evicted queries")};if err:=s.flush();err!=nil{t.Fatal(err)};again,err:=newStore(s.dir);if err!=nil{t.Fatal(err)};if again.overview()["blocked"].(int)!=maxQueries+10{t.Fatal("aggregate not persisted")}
 if err:=s.change(func(v *Settings)error{v.Logging=false;return nil});err!=nil{t.Fatal(err)};if err:=s.clearHistory();err!=nil{t.Fatal(err)};s.record(Query{Time:time.Now()});if len(s.history.Queries)!=0{t.Fatal("logging opt-out ignored")}
}
func fakeUpstream(t *testing.T,handler dns.HandlerFunc)string{t.Helper();tcp,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)};udp,err:=net.ListenPacket("udp",tcp.Addr().String());if err!=nil{tcp.Close();t.Fatal(err)};ready:=make(chan struct{},2)
 servers:=[]*dns.Server{{Listener:tcp,Handler:handler,NotifyStartedFunc:func(){ready<-struct{}{}}},{PacketConn:udp,Handler:handler,NotifyStartedFunc:func(){ready<-struct{}{}}}}
 for _,s:=range servers{go func(s *dns.Server){_ = s.ActivateAndServe()}(s);t.Cleanup(func(){_ = s.Shutdown()})};for i:=0;i<2;i++{select{case <-ready:case <-time.After(3*time.Second):t.Fatal("fake DNS did not start")}};return tcp.Addr().String()
}
func TestForwardingTCPFallbackAndNXDOMAIN(t *testing.T){address:=fakeUpstream(t,func(w dns.ResponseWriter,req *dns.Msg){reply:=new(dns.Msg);reply.SetReply(req);if _,ok:=w.RemoteAddr().(*net.UDPAddr);ok{reply.Truncated=true}else{reply.Answer=[]dns.RR{&dns.A{Hdr:dns.RR_Header{Name:req.Question[0].Name,Rrtype:dns.TypeA,Class:dns.ClassINET,Ttl:60},A:net.ParseIP("192.0.2.42")}}};_ = w.WriteMsg(reply)})
 s:=testStore(t);s.settings.Upstreams=[]string{address};r:=&resolver{store:s}
 for _,transport:=range []string{"udp","tcp"}{req:=new(dns.Msg);req.SetQuestion("example.test.",dns.TypeA);reply,status,_:=r.resolve(req,transport);if status!="allowed"||reply.Truncated||len(reply.Answer)!=1{t.Fatalf("forward failed: %s %v",status,reply)};if reply.Answer[0].(*dns.A).A.String()!="192.0.2.42"{t.Fatal("wrong answer")};req.SetQuestion("blocked.test.",dns.TypeAAAA);reply,status,_=r.resolve(req,transport);if status!="blocked"||reply.Rcode!=dns.RcodeNameError{t.Fatal("blocking failed")}}
}
func TestCNAMEAndUpstreamNXDOMAIN(t *testing.T){address:=fakeUpstream(t,func(w dns.ResponseWriter,req *dns.Msg){reply:=new(dns.Msg);reply.SetReply(req);if req.Question[0].Name=="missing.test."{reply.Rcode=dns.RcodeNameError}else{reply.Answer=[]dns.RR{&dns.CNAME{Hdr:dns.RR_Header{Name:req.Question[0].Name,Rrtype:dns.TypeCNAME,Class:dns.ClassINET,Ttl:60},Target:"blocked.test."}}};_ = w.WriteMsg(reply)})
 s:=testStore(t);s.settings.Upstreams=[]string{address};r:=&resolver{store:s};req:=new(dns.Msg);req.SetQuestion("alias.test.",dns.TypeA);_,status,_:=r.resolve(req,"udp");if status!="blocked"{t.Fatal("CNAME bypass")};req.SetQuestion("missing.test.",dns.TypeA);_,status,_=r.resolve(req,"udp");if status!="notfound"{t.Fatal("upstream NXDOMAIN counted as blocked")}
}
func TestHealthDuringPause(t *testing.T){s:=testStore(t);s.settings.PausedUntil=time.Now().Add(time.Hour);r:=&resolver{store:s};req:=new(dns.Msg);req.SetQuestion("health.quietdns.internal.",dns.TypeTXT);reply,_,_:=r.resolve(req,"udp");if reply.Rcode!=0||len(reply.Answer)!=1{t.Fatal("health check depends on blocking")}}
func TestAPIAuthenticationAndOrigin(t *testing.T){s:=testStore(t);a:=&API{store:s,resolver:&resolver{store:s},setupToken:strings.Repeat("k",32),sessions:map[string]time.Time{}};handler:=a.handler()
 call:=func(method,path,body,origin,cookie string)*httptest.ResponseRecorder{req:=httptest.NewRequest(method,"http://127.0.0.1:8080"+path,strings.NewReader(body));if method!="GET"{req.Header.Set("Content-Type","application/json");req.Header.Set("Origin",origin)};if cookie!=""{req.Header.Set("Cookie",cookie)};w:=httptest.NewRecorder();handler.ServeHTTP(w,req);return w}
 if w:=call("GET","/api/overview","","","");w.Code!=401{t.Fatal("dashboard data is public")}
 body:=fmt.Sprintf(`{"token":%q,"password":"long-test-password","name":"Test","source":"none"}`,a.setupToken)
 if w:=call("POST","/api/setup",body,"http://evil.test","");w.Code!=403{t.Fatal("cross-origin setup accepted")}
 w:=call("POST","/api/setup",body,"http://127.0.0.1:8080","");if w.Code!=200{t.Fatalf("setup: %d %s",w.Code,w.Body)};cookie:=w.Result().Cookies()[0];if !cookie.HttpOnly||cookie.SameSite!=http.SameSiteStrictMode{t.Fatal("unsafe session cookie")}
 if w:=call("GET","/api/overview","","",cookie.String());w.Code!=200{t.Fatal("session not accepted")}
 if w:=call("POST","/api/setup",body,"http://127.0.0.1:8080","");w.Code==200{t.Fatal("setup can overwrite account")}
 if w:=call("POST","/api/rules",`{"domain":"ads.test","kind":"block"}`,"http://127.0.0.1:8080",cookie.String());w.Code!=200{t.Fatal("rule mutation failed")};if blocked,_:=s.policy("ads.test");!blocked{t.Fatal("rule not activated")}
 if w:=call("POST","/api/logout",`{}`,"http://127.0.0.1:8080",cookie.String());w.Code!=200{t.Fatal("logout failed")};if w:=call("GET","/api/overview","","",cookie.String());w.Code!=401{t.Fatal("logout did not revoke session")}
}
func TestFailedUpdatePreservesCache(t *testing.T){s:=testStore(t);s.lists["hagezi-light"]=map[string]bool{"cached.test":true};s.rebuildLocked();if err:=os.WriteFile(filepath.Join(s.dir,"hagezi-light.txt"),[]byte("cached.test\n"),0600);err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel();s.refreshLists(ctx);if blocked,_:=s.policy("cached.test");!blocked{t.Fatal("failed refresh cleared protection")};b,err:=os.ReadFile(filepath.Join(s.dir,"hagezi-light.txt"));if err!=nil||string(b)!="cached.test\n"{t.Fatal("cache overwritten")}
}
