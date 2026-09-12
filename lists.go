package main

import (
 "bufio"
 "context"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "path/filepath"
 "strings"
 "time"
)

var catalog=[]SourceStatus{
 {ID:"hagezi-light",Name:"HaGeZi Light",Description:"A gentle starting point. Blocks common ads and trackers with fewer interruptions.",URL:"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt"},
 {ID:"hagezi-normal",Name:"HaGeZi Normal",Description:"Broader coverage of advertising, tracking and malicious domains. May need occasional allowlist rules.",URL:"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt"},
}
func knownSource(id string)bool {for _,source:=range catalog{if source.ID==id{return true}};return false}
func canonical(s string)string{return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s),"."))}
func validDomain(name string)bool {
 if name!=canonical(name)||len(name)>253||!strings.Contains(name,".")||net.ParseIP(name)!=nil{return false}
 for _,label:=range strings.Split(name,".") {if len(label)==0||len(label)>63||label[0]=='-'||label[len(label)-1]=='-'{return false};for _,ch:=range label {if !(ch>='a'&&ch<='z'||ch>='0'&&ch<='9'||ch=='-'||ch=='_'){return false}}};return true
}
func matches(list map[string]bool,name string)bool {for name=canonical(name);name!=""; {if list[name]{return true};i:=strings.IndexByte(name,'.');if i<0{return false};name=name[i+1:]};return false}
func parseList(content string)(map[string]bool,error) {
 result:=map[string]bool{};scanner:=bufio.NewScanner(strings.NewReader(content));scanner.Buffer(make([]byte,4096),1024*1024)
 for scanner.Scan() {
  line:=strings.TrimSpace(strings.SplitN(scanner.Text(),"#",2)[0]);if line==""||strings.HasPrefix(line,"!"){continue}
  fields:=strings.Fields(line);if net.ParseIP(fields[0])!=nil{fields=fields[1:]}
  for _,field:=range fields {name:=canonical(field);if name=="localhost"||name=="localhost.localdomain"||!strings.Contains(name,"."){continue};if !validDomain(name){return nil,fmt.Errorf("unsupported list entry %q",field)};result[name]=true}
 }
 if err:=scanner.Err();err!=nil{return nil,err};return result,nil
}
var listClient=&http.Client{Timeout:45*time.Second,CheckRedirect:func(req *http.Request,via []*http.Request)error {
 if len(via)>3||req.URL.Scheme!="https"||req.URL.Host!="raw.githubusercontent.com" {return errors.New("unexpected blocklist redirect")};return nil
}}
func (s *Store) refreshLists(ctx context.Context) bool {
 s.mu.Lock();if s.updating{s.refreshPending=true;s.mu.Unlock();return false};s.updating=true;s.mu.Unlock()
 defer func(){s.mu.Lock();s.updating=false;pending:=s.refreshPending;s.refreshPending=false;s.mu.Unlock();if pending&&ctx.Err()==nil{go s.refreshLists(ctx)}}()
 selected:=s.snapshotSettings().Sources
 for _,id:=range selected {
  var source SourceStatus;for _,entry:=range catalog{if entry.ID==id{source=entry}}
  req,err:=http.NewRequestWithContext(ctx,http.MethodGet,source.URL,nil)
  var content []byte;var domains map[string]bool
  if err==nil {
   var response *http.Response;response,err=listClient.Do(req)
   if err==nil {if response.StatusCode!=http.StatusOK {err=fmt.Errorf("provider returned HTTP %d",response.StatusCode)} else {content,err=io.ReadAll(io.LimitReader(response.Body,16*1024*1024+1))};response.Body.Close()}
  }
  if err==nil&&len(content)>16*1024*1024 {err=errors.New("list exceeds 16 MB")}
  if err==nil {domains,err=parseList(string(content))}
  if err==nil&&len(domains)<100 {err=errors.New("list contains fewer than 100 valid domains")}
  if err==nil {err=atomicWrite(filepath.Join(s.dir,id+".txt"),content)}
  s.mu.Lock();status:=s.sourceStatus[id]
  if err!=nil {status.Error=err.Error()} else {s.lists[id]=domains;status.Count=len(domains);status.Updated=time.Now().UTC();status.Error="";s.rebuildLocked()}
  s.sourceStatus[id]=status;s.mu.Unlock()
 }
 return true
}
