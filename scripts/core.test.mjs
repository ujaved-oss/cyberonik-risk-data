import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {calendarDate,collectSnapshot,feedUrls,mergeScores,parseAlerts,parseEpss,parseKev,requestSource,safeUrl,verifyBenchmark} from './core.mjs';

const now=new Date('2026-10-23T12:00:00Z');
const vulnerability=(cve,dateAdded='2026-10-23')=>({cveID:cve,vendorProject:'Vendor',product:'Product',vulnerabilityName:'Sample vulnerability',dateAdded,knownRansomwareCampaignUse:'Unknown',requiredAction:'Apply the vendor update.'});
const catalogue={catalogVersion:'2026.10.23',dateReleased:'2026-10-23T10:00:00Z',count:3,vulnerabilities:[vulnerability('CVE-2026-10001'),{...vulnerability('CVE-2026-10002','2026-10-17'),knownRansomwareCampaignUse:'Known'},vulnerability('CVE-2026-10003','2026-09-24')]};
const rssItem=(url='https://www.cisa.gov/news-events/alerts/2026/10/23/example',date='Fri, 23 Oct 2026 10:00:00 GMT')=>`<item><title><![CDATA[Vendor &amp; security update]]></title><link>${url}</link><pubDate>${date}</pubDate></item>`;
const rss=`<?xml version="1.0"?><rss version="2.0"><channel>${rssItem()}</channel></rss>`;
const benchmark={id:'sample',value:'US$4.44m',label:'Mean breach cost',description:'Historical sample mean, not a customer guarantee.',sourceName:'IBM',sourceUrl:'https://newsroom.ibm.com/sample',period:'2025 study',anchors:['$4.44 million','600 organizations']};
const config={benchmarks:[benchmark]};
const body=(value,url)=>({text:typeof value==='string'?value:JSON.stringify(value),bytes:Buffer.from(typeof value==='string'?value:JSON.stringify(value)),url});
function successfulRequest(url){
  if(url===feedUrls.kev||url===feedUrls.kevFallback)return Promise.resolve(body(catalogue,url));
  if(url===feedUrls.alerts)return Promise.resolve(body(rss,url));
  if(url.startsWith(feedUrls.epss))return Promise.resolve(body({status:'OK',data:catalogue.vulnerabilities.map(item=>({cve:item.cveID,epss:'0.25',percentile:'0.75',date:'2026-10-22'}))},url));
  return Promise.resolve(body('<p>$4.44 million for 600 organizations.</p>',url));
}

test('KEV derives inclusive UTC calendar windows and ransomware references',()=>{
  const parsed=parseKev(catalogue,now);
  assert.equal(parsed.total,3);assert.equal(parsed.addedLast7Days,2);assert.equal(parsed.addedLast30Days,3);assert.equal(parsed.ransomwareKnownCount,1);
  assert.equal(parsed.latest[0].dateAdded,'2026-10-23');
  assert.equal(parseKev(catalogue,new Date('2026-10-24T00:01:00Z')).addedLast7Days,1);
});
test('KEV rejects empty, count mismatch, duplicate, impossible and future data',()=>{
  assert.throws(()=>parseKev({...catalogue,count:0,vulnerabilities:[]},now),/empty/);
  assert.throws(()=>parseKev({...catalogue,count:4},now),/count/);
  assert.throws(()=>parseKev({...catalogue,count:2,vulnerabilities:[catalogue.vulnerabilities[0],catalogue.vulnerabilities[0]]},now),/duplicate/);
  assert.throws(()=>parseKev({...catalogue,count:1,vulnerabilities:[vulnerability('CVE-2026-10001','2026-02-30')]},now),/date/);
  assert.throws(()=>parseKev({...catalogue,dateReleased:'2026-10-24T10:00:00Z'},now),/future/);
  assert.throws(()=>calendarDate('2026-10-24',now),/future/);
});
test('RSS decodes safe text and rejects empty, future, malicious and duplicate links',()=>{
  assert.equal(parseAlerts(rss,now)[0].title,'Vendor & security update');
  assert.throws(()=>parseAlerts('<rss><channel></channel></rss>',now),/Empty/);
  assert.throws(()=>parseAlerts('<!DOCTYPE rss SYSTEM "file:///etc/passwd">'+rss,now),/Invalid RSS/);
  assert.throws(()=>parseAlerts(`<rss><channel>${rssItem('javascript:alert(1)')}</channel></rss>`,now),/Unapproved/);
  assert.throws(()=>parseAlerts(`<rss><channel>${rssItem('https://www.cisa.gov.evil.example/alert')}</channel></rss>`,now),/Unapproved/);
  assert.throws(()=>parseAlerts(`<rss><channel>${rssItem()}${rssItem()}</channel></rss>`,now),/Duplicate/);
  assert.throws(()=>parseAlerts(`<rss><channel>${rssItem(undefined,'Sat, 24 Oct 2026 10:00:00 GMT')}</channel></rss>`,now),/future/);
});
test('EPSS rejects invalid probabilities, dates and unrequested or duplicate CVEs',()=>{
  const requested=['CVE-2026-10001'],record={cve:requested[0],epss:'0.5',percentile:'0.8',date:'2026-10-22'};
  assert.equal(parseEpss({status:'OK',data:[record]},requested,now).get(requested[0]).epss,0.5);
  for(const epss of ['NaN','',-1,1.1,null])assert.throws(()=>parseEpss({status:'OK',data:[{...record,epss}]},requested,now),/EPSS probability/);
  assert.throws(()=>parseEpss({status:'OK',data:[{...record,cve:'CVE-2026-10099'}]},requested,now),/unexpected/);
  assert.throws(()=>parseEpss({status:'OK',data:[{...record,date:'2026-10-24'}]},requested,now),/future/);
  assert.throws(()=>parseEpss({status:'OK',data:[]},requested,now),/empty/);
});
test('score retention matches CVE identities and preserves each score date',()=>{
  const kev=parseKev(catalogue,now),prior={...kev,latest:[{...kev.latest[0],epss:0.1,percentile:0.2,scoreDate:'2026-10-20'},{...kev.latest[1],epss:0.9,percentile:0.99,scoreDate:'2026-10-20'}]};
  const reordered={...kev,latest:[kev.latest[1],kev.latest[2],kev.latest[0]]};
  const result=mergeScores(reordered,null,prior,now);
  assert.equal(result.latest[0].epss,0.9);assert.equal(result.latest[0].scoreDate,'2026-10-20');
  assert.equal(result.latest[1].epss,undefined);assert.equal(result.latest[2].epss,0.1);
});
test('all feed failures preserve last good values and success dates instead of zeroing',async()=>{
  const previous=await collectSnapshot({config,now,request:successfulRequest});
  const later=new Date('2026-10-24T12:00:00Z');
  const result=await collectSnapshot({config,previous,now:later,request:async()=>{throw new Error('offline');}});
  assert.equal(result.generatedAt,later.toISOString());assert.deepEqual(result.kev,previous.kev);assert.deepEqual(result.alerts,previous.alerts);
  for(const key of Object.keys(result.sources)){assert.equal(result.sources[key].status,'error');assert.equal(result.sources[key].lastSuccessAt,now.toISOString());assert.equal(result.sources[key].lastAttemptAt,later.toISOString());}
  assert.equal(result.benchmarks[0].value,previous.benchmarks[0].value);assert.equal(result.benchmarks[0].checkedAt,now.toISOString());assert.equal(result.benchmarks[0].status,'review-required');
});
test('official KEV mirror success is distinct from total failure',async()=>{
  const result=await collectSnapshot({config,now,request:async(url)=>{if(url===feedUrls.kev)throw new Error('403');return successfulRequest(url);}});
  assert.equal(result.sources.kev.status,'ok');assert.equal(result.sources.kev.url,feedUrls.kevFallback);assert.match(result.sources.kev.message,/mirror/);assert.equal(result.kev.total,3);
});
test('unexpected catalogue shrink retains prior catalogue',async()=>{
  const previous=await collectSnapshot({config,now,request:successfulRequest});
  const truncated={...catalogue,count:1,vulnerabilities:[catalogue.vulnerabilities[0]]};
  const result=await collectSnapshot({config,previous,now,request:async(url)=>[feedUrls.kev,feedUrls.kevFallback].includes(url)?body(truncated,url):successfulRequest(url)});
  assert.equal(result.sources.kev.status,'error');assert.equal(result.kev.total,3);assert.match(result.sources.kev.message,/shrank/);
});
test('benchmark mismatch holds curated value, last verification and requires review',async()=>{
  const previous=await collectSnapshot({config,now,request:successfulRequest});
  const result=await collectSnapshot({config,previous,now:new Date('2026-10-24T12:00:00Z'),request:async(url)=>url===benchmark.sourceUrl?body('<p>$5.99 million from a changed source</p>',url):successfulRequest(url)});
  assert.equal(result.benchmarks[0].status,'review-required');assert.equal(result.benchmarks[0].value,'US$4.44m');assert.equal(result.benchmarks[0].checkedAt,now.toISOString());assert.equal(result.sources.benchmarks.status,'error');
});
test('benchmark anchors normalize entities; binary source changes need review',()=>{
  assert.equal(verifyBenchmark(benchmark,body('<p>$4.44&nbsp;million for 600 organizations.</p>')),true);
  const bytes=Buffer.from('reviewed PDF bytes'),hash=createHash('sha256').update(bytes).digest('hex');
  assert.equal(verifyBenchmark({verification:{kind:'sha256',hash}},{bytes}),true);
  assert.equal(verifyBenchmark({verification:{kind:'sha256',hash}},{bytes:Buffer.from('changed')}),false);
});
test('annual-report discovery flags a newer publication without copying new values',async()=>{
  const ic3={...benchmark,id:'losses',sourceUrl:'https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf'};
  const discovery={sourceUrl:'https://www.ic3.gov/AnnualReport/Reports',currentReportYear:2025,linkPattern:'/AnnualReport/Reports/(20\\d{2})_IC3Report\\.pdf'};
  const result=await collectSnapshot({config:{benchmarks:[ic3],releaseDiscovery:[discovery]},now,request:async(url)=>url===discovery.sourceUrl?body('<a href="/AnnualReport/Reports/2026_IC3Report.pdf">2026 report</a>',url):successfulRequest(url)});
  assert.equal(result.benchmarks[0].status,'review-required');assert.equal(result.sources.benchmarks.status,'error');assert.equal(result.benchmarks[0].value,ic3.value);
});
test('bounded source fetching retries once and rejects oversized data and unsafe redirects',async()=>{
  let calls=0;
  const result=await requestSource(feedUrls.alerts,{fetchImpl:async()=>{calls++;return calls===1?new Response('retry',{status:503}):new Response(rss,{status:200});}});
  assert.equal(calls,2);assert.match(result.text,/<rss/);
  await assert.rejects(requestSource(feedUrls.alerts,{maxBytes:4,retries:0,fetchImpl:async()=>new Response('12345')}),/size limit/);
  await assert.rejects(requestSource(feedUrls.alerts,{retries:0,fetchImpl:async()=>new Response(null,{status:302,headers:{location:'http://127.0.0.1/private'}})}),/Unapproved/);
  assert.throws(()=>safeUrl('https://user:pass@www.cisa.gov/'),/Unapproved/);
});
