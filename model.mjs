export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function filterQueries(queries, search, status) {
 const term = search.trim().toLowerCase();
 return queries.filter(q => (!status || q.status === status) && `${q.domain} ${q.client}`.toLowerCase().includes(term));
}
export function percent(blocked,total) { return total ? (blocked / total * 100).toFixed(1) : '0.0'; }
export function chartPoints(buckets, now = Date.now()) {
 const end = Math.floor(now / 3600000) * 3600000;
 return Array.from({length:24}, (_, i) => {
  const start = end - (23-i)*3600000;
  const samples=buckets.filter(b=>new Date(b.time).getTime()>=start&&new Date(b.time).getTime()<start+3600000);
  return {time:start,total:samples.reduce((a,b)=>a+b.total,0),blocked:samples.reduce((a,b)=>a+b.blocked,0)};
 });
}
