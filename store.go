package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "sync"
 "time"
)

const maxQueries = 2000

type Rule struct {
 Domain string `json:"domain"`
 Kind string `json:"kind"`
}
type Settings struct {
 Name string `json:"name"`
 Upstreams []string `json:"upstreams"`
 Sources []string `json:"sources"`
 Rules []Rule `json:"rules"`
 Logging bool `json:"logging"`
 PasswordHash string `json:"passwordHash,omitempty"`
 PasswordSalt string `json:"passwordSalt,omitempty"`
 PausedUntil time.Time `json:"pausedUntil"`
}
type Query struct {
 Time time.Time `json:"time"`
 Domain string `json:"domain"`
 Type string `json:"type"`
 Client string `json:"client"`
 Status string `json:"status"`
 Reason string `json:"reason"`
 Latency float64 `json:"latency"`
}
type Bucket struct {
 Time time.Time `json:"time"`
 Total int `json:"total"`
 Blocked int `json:"blocked"`
 Errors int `json:"errors"`
 Latency float64 `json:"latency"`
}
type History struct {
 Queries []Query `json:"queries"`
 Buckets []Bucket `json:"buckets"`
}
type SourceStatus struct {
 ID string `json:"id"`
 Name string `json:"name"`
 Description string `json:"description"`
 URL string `json:"url"`
 Enabled bool `json:"enabled"`
 Count int `json:"count"`
 Updated time.Time `json:"updated"`
 Error string `json:"error"`
}
type Store struct {
 mu sync.RWMutex
 dir string
 settings Settings
 history History
 lists map[string]map[string]bool
 sourceStatus map[string]SourceStatus
 blocked, allowed map[string]bool
 updating bool
 refreshPending bool
 persistenceError string
}

func newStore(dir string) (*Store, error) {
 if err := os.MkdirAll(dir, 0700); err != nil { return nil, err }
 s := &Store{dir:dir, lists:map[string]map[string]bool{}, sourceStatus:map[string]SourceStatus{}}
 s.settings = Settings{Name:"My network",Upstreams:[]string{"1.1.1.1:53","9.9.9.9:53"},Sources:[]string{"hagezi-light"},Rules:[]Rule{},Logging:true}
 if err := readJSON(filepath.Join(dir,"settings.json"), &s.settings); err != nil && !errors.Is(err,os.ErrNotExist) { return nil,fmt.Errorf("read settings: %w",err) }
 if err := validateSettings(s.settings); err != nil { return nil,err }
 if err := readJSON(filepath.Join(dir,"history.json"), &s.history); err != nil && !errors.Is(err,os.ErrNotExist) { return nil,fmt.Errorf("read history: %w",err) }
 if !s.settings.Logging { s.history = History{} }
 s.pruneLocked(time.Now())
 for _, source := range catalog {
  status := source
  path := filepath.Join(dir,source.ID+".txt")
  if content, err := os.ReadFile(path); err == nil {
   domains, err := parseList(string(content))
   if err == nil { s.lists[source.ID] = domains; status.Count = len(domains); if st,err:=os.Stat(path);err==nil {status.Updated=st.ModTime()} } else { status.Error="Cached list is invalid. Refresh to recover." }
  }
  s.sourceStatus[source.ID]=status
 }
 s.rebuildLocked()
 return s,nil
}
func readJSON(path string, into any) error { b,err:=os.ReadFile(path);if err!=nil{return err};return json.Unmarshal(b,into) }
func atomicWrite(path string, data []byte) error {
 f,err:=os.CreateTemp(filepath.Dir(path),".quietdns-*");if err!=nil{return err}
 defer os.Remove(f.Name())
 if err=f.Chmod(0600);err!=nil {f.Close();return err}
 if _,err=f.Write(data);err!=nil {f.Close();return err}
 if err=f.Sync();err!=nil {f.Close();return err};if err=f.Close();err!=nil{return err}
 return os.Rename(f.Name(),path)
}
func writeJSON(path string,v any) error { b,err:=json.MarshalIndent(v,"","  ");if err!=nil{return err};return atomicWrite(path,b) }
func (s *Store) snapshotSettings() Settings {
 s.mu.RLock();defer s.mu.RUnlock()
 v:=s.settings;v.Upstreams=append([]string{},v.Upstreams...);v.Sources=append([]string{},v.Sources...);v.Rules=append([]Rule{},v.Rules...);return v
}
func (s *Store) upstreams() []string {s.mu.RLock();defer s.mu.RUnlock();return append([]string{},s.settings.Upstreams...)}
func validateSettings(v Settings) error {
 if len(strings.TrimSpace(v.Name))<1 || len(v.Name)>60 {return errors.New("Network name must be 1–60 characters.")}
 if len(v.Upstreams)<1 || len(v.Upstreams)>3 {return errors.New("Choose between one and three upstream DNS servers.")}
 for _,address:=range v.Upstreams {
  host,port,err:=net.SplitHostPort(address);ip:=net.ParseIP(host)
  if err!=nil || ip==nil || port!="53" || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {return errors.New("Upstreams must be IP addresses on port 53, such as 1.1.1.1:53.")}
  if ip.String()==os.Getenv("BIND_IP") {return errors.New("The upstream cannot point back to this DNS server.")}
 }
 if len(v.Sources)>len(catalog) {return errors.New("Too many blocklists.")}
 seen:=map[string]bool{}
 for _,id:=range v.Sources {if !knownSource(id)||seen[id] {return errors.New("Unknown or duplicate blocklist.")};seen[id]=true}
 if len(v.Rules)>10000 {return errors.New("The custom rule limit is 10,000.")}
 for _,r:=range v.Rules {if !validDomain(r.Domain)||(r.Kind!="allow"&&r.Kind!="block") {return errors.New("Rules need a valid domain and an allow or block action.")}}
 return nil
}
func (s *Store) change(fn func(*Settings) error) error {
 s.mu.Lock();defer s.mu.Unlock()
 data,_:=json.Marshal(s.settings);var next Settings;_ = json.Unmarshal(data,&next)
 if err:=fn(&next);err!=nil{return err};if err:=validateSettings(next);err!=nil{return err}
 if err:=writeJSON(filepath.Join(s.dir,"settings.json"),next);err!=nil{return err}
 s.settings=next;s.rebuildLocked();return nil
}
func (s *Store) rebuildLocked() {
 s.blocked=map[string]bool{"blocked.test":true};s.allowed=map[string]bool{}
 for _,id:=range s.settings.Sources {for domain:=range s.lists[id] {s.blocked[domain]=true}}
 for _,rule:=range s.settings.Rules {if rule.Kind=="allow" {s.allowed[rule.Domain]=true} else {s.blocked[rule.Domain]=true}}
}
func (s *Store) policy(name string) (blocked,allowed bool) {
 s.mu.RLock();defer s.mu.RUnlock()
 allowed=matches(s.allowed,name)
 blocked=time.Now().After(s.settings.PausedUntil)&&!allowed&&matches(s.blocked,name)
 return
}
func (s *Store) pruneLocked(now time.Time) {
 cutoff:=now.Add(-24*time.Hour)
 i:=0;for i<len(s.history.Buckets)&&s.history.Buckets[i].Time.Before(cutoff) {i++};s.history.Buckets=append([]Bucket{},s.history.Buckets[i:]...)
 i=0;for i<len(s.history.Queries)&&s.history.Queries[i].Time.Before(cutoff) {i++};s.history.Queries=append([]Query{},s.history.Queries[i:]...)
 if len(s.history.Queries)>maxQueries {s.history.Queries=s.history.Queries[len(s.history.Queries)-maxQueries:]}
}
func (s *Store) record(q Query) {
 s.mu.Lock();defer s.mu.Unlock()
 if !s.settings.Logging {return}
 stamp:=q.Time.Truncate(5*time.Minute)
 n:=len(s.history.Buckets)
 if n==0 || !s.history.Buckets[n-1].Time.Equal(stamp) {s.history.Buckets=append(s.history.Buckets,Bucket{Time:stamp});s.pruneLocked(q.Time);n=len(s.history.Buckets)}
 b:=&s.history.Buckets[n-1];b.Total++;b.Latency+=q.Latency
 if q.Status=="blocked" {b.Blocked++};if q.Status=="error" {b.Errors++}
 if len(s.history.Queries)>=maxQueries {copy(s.history.Queries,s.history.Queries[1:]);s.history.Queries=s.history.Queries[:maxQueries-1]}
 s.history.Queries=append(s.history.Queries,q)
}
func (s *Store) flush() error {
 s.mu.Lock();defer s.mu.Unlock();s.pruneLocked(time.Now())
 err:=writeJSON(filepath.Join(s.dir,"history.json"),s.history)
 s.persistenceError="";if err!=nil {s.persistenceError="Query history could not be saved. Check the data volume."};return err
}
func (s *Store) clearHistory() error {
 s.mu.Lock();defer s.mu.Unlock()
 if err:=writeJSON(filepath.Join(s.dir,"history.json"),History{});err!=nil{return err};s.history=History{};return nil
}
func (s *Store) overview() map[string]any {
 s.mu.RLock();defer s.mu.RUnlock()
 buckets:=[]Bucket{};total,blocked,failures:=0,0,0;latency:=0.0
 for _,b:=range s.history.Buckets {if b.Time.After(time.Now().Add(-24*time.Hour)) {buckets=append(buckets,b);total+=b.Total;blocked+=b.Blocked;failures+=b.Errors;latency+=b.Latency}}
 queries:=[]Query{};clients:=map[string]bool{};domains:=map[string]int{}
 for i:=len(s.history.Queries)-1;i>=0;i-- {q:=s.history.Queries[i];if q.Time.Before(time.Now().Add(-24*time.Hour)){continue};queries=append(queries,q);clients[q.Client]=true;if q.Status=="blocked"{domains[q.Domain]++}}
 type top struct {Domain string `json:"domain"`;Count int `json:"count"`};tops:=[]top{}
 for d,n:=range domains {tops=append(tops,top{d,n})};sort.Slice(tops,func(i,j int)bool{return tops[i].Count>tops[j].Count});if len(tops)>5{tops=tops[:5]}
 sources:=[]SourceStatus{};for _,src:=range catalog {v:=s.sourceStatus[src.ID];for _,id:=range s.settings.Sources {if id==src.ID{v.Enabled=true}};sources=append(sources,v)}
 avg:=0.0;if total>0 {avg=latency/float64(total)}
 return map[string]any{"name":s.settings.Name,"total":total,"blocked":blocked,"errors":failures,"latency":avg,"clients":len(clients),"domains":len(s.blocked),"buckets":buckets,"queries":queries,"topDomains":tops,"sources":sources,"pausedUntil":s.settings.PausedUntil,"logging":s.settings.Logging,"updating":s.updating,"persistenceError":s.persistenceError,"version":version}
}
