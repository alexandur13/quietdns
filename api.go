package main

import (
 "context"
 "crypto/pbkdf2"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "embed"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "io/fs"
 "net"
 "net/http"
 "net/url"
 "strings"
 "sync"
 "time"

 "github.com/miekg/dns"
)

//go:embed web/*
var assets embed.FS

type API struct {
 store *Store
 resolver *resolver
 setupToken string
 mu sync.Mutex
 sessions map[string]time.Time
 attempts int
 window time.Time
}
func randomToken()string {b:=make([]byte,32);if _,err:=rand.Read(b);err!=nil{panic(err)};return hex.EncodeToString(b)}
func passwordHash(password,salt string)string {key,err:=pbkdf2.Key(sha256.New,password,[]byte(salt),210000,32);if err!=nil{panic(err)};return hex.EncodeToString(key)}
func equalSecret(a,b string)bool {x:=sha256.Sum256([]byte(a));y:=sha256.Sum256([]byte(b));return subtle.ConstantTimeCompare(x[:],y[:])==1}
func jsonReply(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json");w.WriteHeader(status);_ = json.NewEncoder(w).Encode(v)}
func apiError(w http.ResponseWriter,status int,message string){jsonReply(w,status,map[string]string{"error":message})}
func decode(w http.ResponseWriter,r *http.Request,v any)error {
 decoder:=json.NewDecoder(http.MaxBytesReader(w,r.Body,64*1024));decoder.DisallowUnknownFields()
 if err:=decoder.Decode(v);err!=nil{return errors.New("Invalid request. Check the supplied fields.")}
 if err:=decoder.Decode(new(any));err!=io.EOF{return errors.New("Send one JSON object per request.")};return nil
}
func (a *API) authenticated(r *http.Request)bool {
 cookie,err:=r.Cookie("quietdns_session");if err!=nil{return false};a.mu.Lock();defer a.mu.Unlock()
 expiry,ok:=a.sessions[cookie.Value];if ok&&time.Now().Before(expiry){return true};delete(a.sessions,cookie.Value);return false
}
func (a *API) newSession(w http.ResponseWriter,r *http.Request) {
 token:=randomToken();expiry:=time.Now().Add(12*time.Hour)
 a.mu.Lock();for key,until:=range a.sessions{if time.Now().After(until){delete(a.sessions,key)}};if len(a.sessions)>=128{a.sessions=map[string]time.Time{}};a.sessions[token]=expiry;a.mu.Unlock()
 http.SetCookie(w,&http.Cookie{Name:"quietdns_session",Value:token,Path:"/",HttpOnly:true,Secure:r.TLS!=nil,SameSite:http.SameSiteStrictMode,Expires:expiry})
}
func (a *API) authAttempt()bool {
 a.mu.Lock();defer a.mu.Unlock();if time.Since(a.window)>time.Minute{a.window=time.Now();a.attempts=0};a.attempts++;return a.attempts<=10
}
func allowedHost(host string)bool {
 if h,_,err:=net.SplitHostPort(host);err==nil{host=h};host=strings.Trim(host,"[]")
 if host=="localhost"{return true};ip:=net.ParseIP(host);return ip!=nil&&(ip.IsPrivate()||ip.IsLoopback()||ip.IsLinkLocalUnicast())
}
func (a *API) handler()http.Handler {
 web,_:=fs.Sub(assets,"web");files:=http.FileServer(http.FS(web))
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("X-Frame-Options","DENY");w.Header().Set("Referrer-Policy","no-referrer")
  w.Header().Set("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
  w.Header().Set("Cache-Control","no-store")
  if !allowedHost(r.Host){apiError(w,403,"Open QuietDNS using its private IP address.");return}
  if !strings.HasPrefix(r.URL.Path,"/api/") {if r.Method!="GET"&&r.Method!="HEAD"{w.WriteHeader(405);return};files.ServeHTTP(w,r);return}
  if r.Method!="GET" {
   if !strings.HasPrefix(r.Header.Get("Content-Type"),"application/json"){apiError(w,415,"Use application/json.");return}
   origin,err:=url.Parse(r.Header.Get("Origin"));scheme:="http";if r.TLS!=nil{scheme="https"}
   if err!=nil||origin.Host!=r.Host||origin.Scheme!=scheme {apiError(w,403,"Request origin does not match this dashboard.");return}
  }
  a.route(w,r)
 })
}
func (a *API) route(w http.ResponseWriter,r *http.Request) {
 path:=r.URL.Path
 if path=="/api/status"&&r.Method=="GET" {jsonReply(w,200,map[string]any{"setupRequired":a.store.snapshotSettings().PasswordHash=="","authenticated":a.authenticated(r),"version":version});return}
 if path=="/api/setup"&&r.Method=="POST" {
  if !a.authAttempt(){apiError(w,429,"Too many attempts. Try again in one minute.");return}
  var input struct {Token string `json:"token"`;Password string `json:"password"`;Name string `json:"name"`;Source string `json:"source"`}
  if err:=decode(w,r,&input);err!=nil{apiError(w,400,err.Error());return}
  if a.setupToken==""||!equalSecret(input.Token,a.setupToken){apiError(w,403,"Setup key is incorrect. Use the key printed by the installer.");return}
  if len(input.Password)<12||len(input.Password)>128{apiError(w,400,"Choose a password with 12–128 characters.");return}
  salt:=randomToken();hash:=passwordHash(input.Password,salt)
  err:=a.store.change(func(s *Settings)error{if s.PasswordHash!=""{return errors.New("Setup is already complete.")};s.Name=strings.TrimSpace(input.Name);s.PasswordSalt=salt;s.PasswordHash=hash;s.Sources=[]string{};if input.Source!="none"{s.Sources=[]string{input.Source}};return nil})
  if err!=nil{apiError(w,400,err.Error());return};a.newSession(w,r);go a.store.refreshLists(context.WithoutCancel(r.Context()));jsonReply(w,200,map[string]bool{"ok":true});return
 }
 if path=="/api/login"&&r.Method=="POST" {
  if !a.authAttempt(){apiError(w,429,"Too many attempts. Try again in one minute.");return}
  var input struct {Password string `json:"password"`};if err:=decode(w,r,&input);err!=nil{apiError(w,400,err.Error());return}
  s:=a.store.snapshotSettings();if len(input.Password)>128||s.PasswordHash==""||!equalSecret(passwordHash(input.Password,s.PasswordSalt),s.PasswordHash){apiError(w,401,"Password is incorrect.");return};a.newSession(w,r);jsonReply(w,200,map[string]bool{"ok":true});return
 }
 if !a.authenticated(r){apiError(w,401,"Sign in to continue.");return}
 switch {
 case path=="/api/logout"&&r.Method=="POST":
  cookie,_:=r.Cookie("quietdns_session");a.mu.Lock();delete(a.sessions,cookie.Value);a.mu.Unlock();http.SetCookie(w,&http.Cookie{Name:"quietdns_session",Path:"/",MaxAge:-1,HttpOnly:true,SameSite:http.SameSiteStrictMode});jsonReply(w,200,map[string]bool{"ok":true})
 case path=="/api/overview"&&r.Method=="GET":jsonReply(w,200,a.store.overview())
 case path=="/api/settings"&&r.Method=="GET":
  s:=a.store.snapshotSettings();s.PasswordHash="";s.PasswordSalt="";jsonReply(w,200,s)
 case path=="/api/settings"&&r.Method=="PUT":
  var input struct{Name string `json:"name"`;Upstreams []string `json:"upstreams"`;Logging bool `json:"logging"`}
  if err:=decode(w,r,&input);err!=nil{apiError(w,400,err.Error());return}
  err:=a.store.change(func(s *Settings)error{s.Name=strings.TrimSpace(input.Name);s.Upstreams=input.Upstreams;s.Logging=input.Logging;return nil})
  if err==nil&&!input.Logging{err=a.store.clearHistory()};if err!=nil{apiError(w,400,err.Error());return};jsonReply(w,200,map[string]bool{"ok":true})
 case path=="/api/rules"&&r.Method=="POST":
  var rule Rule;if err:=decode(w,r,&rule);err!=nil{apiError(w,400,err.Error());return};rule.Domain=canonical(rule.Domain)
  err:=a.store.change(func(s *Settings)error{for i,current:=range s.Rules{if current.Domain==rule.Domain{s.Rules[i]=rule;return nil}};s.Rules=append(s.Rules,rule);return nil})
  if err!=nil{apiError(w,400,err.Error());return};jsonReply(w,200,map[string]bool{"ok":true})
 case path=="/api/rules"&&r.Method=="DELETE":
  var input struct{Domain string `json:"domain"`};if err:=decode(w,r,&input);err!=nil{apiError(w,400,err.Error());return}
  err:=a.store.change(func(s *Settings)error{next:=[]Rule{};for _,rule:=range s.Rules{if rule.Domain!=canonical(input.Domain){next=append(next,rule)}};s.Rules=next;return nil})
  if err!=nil{apiError(w,500,err.Error());return};jsonReply(w,200,map[string]bool{"ok":true})
 case path=="/api/pause"&&r.Method=="POST":
  var input struct{Minutes int `json:"minutes"`};if err:=decode(w,r,&input);err!=nil{apiError(w,400,err.Error());return};if input.Minutes!=0&&input.Minutes!=5&&input.Minutes!=30{apiError(w,400,"Choose 0, 5 or 30 minutes.");return}
  err:=a.store.change(func(s *Settings)error{s.PausedUntil=time.Time{};if input.Minutes>0{s.PausedUntil=time.Now().Add(time.Duration(input.Minutes)*time.Minute)};return nil});if err!=nil{apiError(w,500,err.Error());return};jsonReply(w,200,map[string]bool{"ok":true})
 case path=="/api/sources"&&r.Method=="POST":
  var input struct{ID string `json:"id"`;Enabled bool `json:"enabled"`};if err:=decode(w,r,&input);err!=nil{apiError(w,400,err.Error());return};if !knownSource(input.ID){apiError(w,400,"Unknown blocklist.");return}
  err:=a.store.change(func(s *Settings)error{next:=[]string{};for _,id:=range s.Sources{if id!=input.ID{next=append(next,id)}};if input.Enabled{next=append(next,input.ID)};s.Sources=next;return nil});if err!=nil{apiError(w,500,err.Error());return};if input.Enabled{go a.store.refreshLists(context.WithoutCancel(r.Context()))};jsonReply(w,200,map[string]bool{"ok":true})
 case path=="/api/refresh"&&r.Method=="POST":go a.store.refreshLists(context.WithoutCancel(r.Context()));jsonReply(w,202,map[string]bool{"ok":true})
 case path=="/api/history"&&r.Method=="DELETE":if err:=a.store.clearHistory();err!=nil{apiError(w,500,err.Error());return};jsonReply(w,200,map[string]bool{"ok":true})
 case path=="/api/check"&&r.Method=="POST":
  results:=[]map[string]any{}
  for _,transport:=range []string{"udp","tcp"}{req:=new(dns.Msg);req.SetQuestion("example.com.",dns.TypeA);reply,status,reason:=a.resolver.resolve(req,transport);results=append(results,map[string]any{"name":strings.ToUpper(transport)+" upstream","ok":reply.Rcode==dns.RcodeSuccess&&len(reply.Answer)>0,"detail":status+": "+reason})}
  blocked,_:=a.store.policy("blocked.test.");results=append(results,map[string]any{"name":"Blocking rules","ok":blocked,"detail":"Reserved blocked.test domain"});jsonReply(w,200,results)
 default:apiError(w,404,"Endpoint not found.")
 }
}
