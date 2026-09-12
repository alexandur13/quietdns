package main

import (
 "context"
 "errors"
 "fmt"
 "log"
 "net"
 "net/http"
 "os"
 "os/signal"
 "path/filepath"
 "syscall"
 "time"

 "github.com/miekg/dns"
)

var version="0.2.0-dev"
func env(key,fallback string)string{if value:=os.Getenv(key);value!=""{return value};return fallback}
func healthCheck()error {
 address:=env("DNS_ADDR",":1053");_,port,err:=net.SplitHostPort(address);if err!=nil{return err}
 for _,transport:=range []string{"udp","tcp"} {
  req:=new(dns.Msg);req.SetQuestion("health.quietdns.internal.",dns.TypeTXT)
  answer,_,err:=(&dns.Client{Net:transport,Timeout:time.Second}).Exchange(req,net.JoinHostPort("127.0.0.1",port))
  if err!=nil{return err};if answer.Rcode!=dns.RcodeSuccess||len(answer.Answer)!=1{return errors.New("DNS health check failed")}
 }
 return nil
}
func run()error {
 if len(os.Args)>1&&os.Args[1]=="check"{return healthCheck()}
 store,err:=newStore(env("DATA_DIR","./data"));if err!=nil{return err}
 if len(os.Args)>1&&os.Args[1]=="reset-password" {
  err:=store.change(func(s *Settings)error{s.PasswordHash="";s.PasswordSalt="";return nil});if err!=nil{return err};fmt.Println("Administrator password reset. Restart QuietDNS and reopen setup with the installation key.");return nil
 }
 setupToken:=os.Getenv("SETUP_TOKEN")
 if store.snapshotSettings().PasswordHash=="" {if len(setupToken)<24 {setupToken=randomToken();log.Printf("First-run setup key: %s",setupToken)}}
 r:=&resolver{store:store,slots:make(chan struct{},128)}
 api:=&API{store:store,resolver:r,setupToken:setupToken,sessions:map[string]time.Time{}}
 udp,err:=net.ListenPacket("udp",env("DNS_ADDR",":1053"));if err!=nil{return err};defer udp.Close()
 tcp,err:=net.Listen("tcp",env("DNS_ADDR",":1053"));if err!=nil{return err};defer tcp.Close()
 admin,err:=net.Listen("tcp",env("HTTP_ADDR",":8080"));if err!=nil{return err};defer admin.Close()
 servers:=[]*dns.Server{{PacketConn:udp,Handler:r},{Listener:tcp,Handler:r,ReadTimeout:5*time.Second,WriteTimeout:5*time.Second}}
 web:=&http.Server{Handler:api.handler(),ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:30*time.Second,IdleTimeout:60*time.Second,MaxHeaderBytes:16384}
 failures:=make(chan error,3)
 for _,server:=range servers{go func(s *dns.Server){failures<-s.ActivateAndServe()}(server)}
 go func(){failures<-web.Serve(admin)}()
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
 done:=make(chan struct{});go func(){defer close(done);flush:=time.NewTicker(30*time.Second);defer flush.Stop();refresh:=time.NewTicker(24*time.Hour);defer refresh.Stop()
  if store.snapshotSettings().PasswordHash!=""{go store.refreshLists(ctx)}
  for {select{case <-ctx.Done():return;case <-flush.C:if err:=store.flush();err!=nil{log.Printf("history persistence: %v",err)};case <-refresh.C:if store.snapshotSettings().PasswordHash!=""{go store.refreshLists(ctx)}}}
 }()
 log.Printf("QuietDNS %s ready: DNS %s (UDP/TCP), dashboard %s; data %s",version,udp.LocalAddr(),admin.Addr(),filepath.Clean(store.dir))
 var failure error;select{case <-ctx.Done():case failure=<-failures:};stop()
 shutdown,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel();_ = web.Shutdown(shutdown)
 for _,server:=range servers{_ = server.ShutdownContext(shutdown)};<-done
 if err:=store.flush();err!=nil{log.Printf("history persistence: %v",err)}
 if errors.Is(failure,http.ErrServerClosed)||errors.Is(failure,net.ErrClosed){return nil};return failure
}
func main(){if err:=run();err!=nil{log.Fatal(err)}}
