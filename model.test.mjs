import test from 'node:test';
import assert from 'node:assert/strict';
import {escapeHTML,filterQueries,percent,chartPoints} from '../web/model.mjs';
test('query filtering combines client/domain search and status',()=>{const rows=[{domain:'Ads.test',client:'192.168.1.2',status:'blocked'},{domain:'example.test',client:'192.168.1.3',status:'allowed'}];assert.equal(filterQueries(rows,'ADS','blocked').length,1);assert.equal(filterQueries(rows,'.3','blocked').length,0);assert.equal(filterQueries(rows,'.3','').length,1)});
test('untrusted domains are rendered as text',()=>{assert.equal(escapeHTML('<img src=x onerror="alert(1)">'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;')});
test('empty statistics never produce NaN',()=>assert.equal(percent(0,0),'0.0'));
test('chart fills missing hours without inventing traffic',()=>{const now=Date.UTC(2026,8,12,12,30);const result=chartPoints([{time:new Date(now).toISOString(),total:5,blocked:2}],now);assert.equal(result.length,24);assert.equal(result[23].total,5);assert.equal(result[23].blocked,2);assert.equal(result[0].total,0)});
