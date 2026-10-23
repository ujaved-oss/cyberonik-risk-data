import {createHash} from 'node:crypto';

export const feedUrls = {
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  kevFallback: 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
  alerts: 'https://www.cisa.gov/cybersecurity-advisories/alerts.xml',
  epss: 'https://api.first.org/data/v1/epss',
};
const sourceHosts = new Set(['www.cisa.gov', 'cisa.gov', 'raw.githubusercontent.com', 'api.first.org', 'www.first.org', 'newsroom.ibm.com', 'www.ibm.com', 'ibm.com', 'www.weforum.org', 'weforum.org', 'reports.weforum.org', 'www.ic3.gov', 'ic3.gov', 'www.fbi.gov', 'fbi.gov']);
const dayMs = 86_400_000;
const cvePattern = /^CVE-\d{4}-\d{4,}$/;
const names = {kev:'CISA Known Exploited Vulnerabilities', alerts:'CISA cybersecurity advisories', epss:'FIRST EPSS', benchmarks:'Published research source checks'};

export function safeUrl(value, hosts = sourceHosts) {
  if (typeof value !== 'string' || value.length > 3000) throw new Error('Invalid source URL');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.port || !hosts.has(url.hostname.toLowerCase())) throw new Error('Unapproved source URL');
  return url.href;
}
function text(value, field, maximum = 2000) {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) throw new Error(`Invalid ${field}`);
  return value.trim();
}
export function calendarDate(value, now = new Date()) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error('Invalid calendar date');
  const date = new Date(value + 'T00:00:00.000Z');
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0,10) !== value || value > now.toISOString().slice(0,10)) throw new Error('Invalid or future calendar date');
  return value;
}
function instant(value, now, field) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`Missing ${field}`);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.getTime() > now.getTime() + 300_000 || date.getTime() < Date.UTC(1990,0,1)) throw new Error(`Invalid or future ${field}`);
  return date.toISOString();
}
export function parseKev(raw, now = new Date()) {
  const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!data || !Array.isArray(data.vulnerabilities) || data.vulnerabilities.length === 0 || data.vulnerabilities.length > 100_000 || !Number.isInteger(data.count) || data.count !== data.vulnerabilities.length) throw new Error('Invalid or empty KEV catalogue/count');
  const catalogueVersion = text(data.catalogVersion, 'KEV catalogue version', 100);
  const dateReleased = instant(data.dateReleased, now, 'KEV release date');
  const seen = new Set();
  const entries = data.vulnerabilities.map(item => {
    if (!item || !cvePattern.test(item.cveID) || seen.has(item.cveID)) throw new Error('Invalid or duplicate KEV CVE');
    seen.add(item.cveID);
    if (!['Known','Unknown'].includes(item.knownRansomwareCampaignUse)) throw new Error('Invalid ransomware classification');
    return {
      cve:item.cveID, vendor:text(item.vendorProject,'KEV vendor',500), product:text(item.product,'KEV product',1000), name:text(item.vulnerabilityName,'KEV name',1500),
      dateAdded:calendarDate(item.dateAdded,now), ransomware:item.knownRansomwareCampaignUse === 'Known', action:text(item.requiredAction,'KEV action',3000),
      url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext='+encodeURIComponent(item.cveID),
    };
  }).sort((a,b) => b.dateAdded.localeCompare(a.dateAdded) || b.cve.localeCompare(a.cve));
  if (entries.some(item => item.dateAdded > dateReleased.slice(0,10))) throw new Error('KEV addition follows catalogue release');
  const today = Date.parse(now.toISOString().slice(0,10)+'T00:00:00Z');
  const countSince = days => entries.filter(item => Date.parse(item.dateAdded+'T00:00:00Z') >= today-(days-1)*dayMs).length;
  return {catalogueVersion,dateReleased,total:entries.length,addedLast7Days:countSince(7),addedLast30Days:countSince(30),ransomwareKnownCount:entries.filter(item=>item.ransomware).length,latest:entries.slice(0,12)};
}

function entities(value) {
  return value.replace(/&(?:#(\d+)|#x([\da-f]+)|(amp|lt|gt|quot|apos|nbsp));/gi, (all, dec, hex, named) => {
    if (named) return {amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",nbsp:' '}[named.toLowerCase()];
    const code = Number.parseInt(dec || hex, dec ? 10 : 16);
    return code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) ? String.fromCodePoint(code) : '';
  });
}
export function plainText(value) {
  return entities(value.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ').replace(/<[^>]*>/g,' ')).replace(/[\u0000-\u001f]/g,' ').replace(/\s+/g,' ').trim();
}
function xmlField(item, name) {
  const match = item.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${name}>`,'i'));
  if (!match) throw new Error(`Missing advisory ${name}`);
  return plainText(match[1]);
}
export function parseAlerts(xml, now = new Date()) {
  if (typeof xml !== 'string' || /<!DOCTYPE|<!ENTITY/i.test(xml) || !/<rss(?:\s|>)/i.test(xml) || !/<channel(?:\s|>)/i.test(xml)) throw new Error('Invalid RSS feed');
  const items = [...xml.matchAll(/<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi)];
  if (!items.length || items.length > 10_000) throw new Error('Empty or excessive advisory feed');
  const seen = new Set();
  return items.map(([,item]) => {
    const url = safeUrl(xmlField(item,'link'),new Set(['www.cisa.gov','cisa.gov']));
    if (seen.has(url)) throw new Error('Duplicate advisory URL');
    seen.add(url);
    return {title:text(xmlField(item,'title'),'advisory title',1000),url,publishedAt:instant(xmlField(item,'pubDate'),now,'advisory publication date')};
  }).sort((a,b)=>b.publishedAt.localeCompare(a.publishedAt)).slice(0,12);
}
export function parseEpss(raw, requested, now = new Date()) {
  const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!data || data.status !== 'OK' || !Array.isArray(data.data) || !data.data.length || data.data.length > requested.length) throw new Error('Invalid or empty EPSS response');
  const allowed = new Set(requested), result = new Map();
  for (const item of data.data) {
    if (!item || !cvePattern.test(item.cve) || !allowed.has(item.cve) || result.has(item.cve)) throw new Error('Invalid, unexpected or duplicate EPSS CVE');
    const number = (input, field) => {
      if (!['string','number'].includes(typeof input) || String(input).trim() === '') throw new Error(`Invalid ${field}`);
      const value = Number(input);
      if (!Number.isFinite(value) || value < 0 || value > 1) throw new Error(`Invalid ${field}`);
      return value;
    };
    result.set(item.cve,{epss:number(item.epss,'EPSS probability'),percentile:number(item.percentile,'EPSS percentile'),scoreDate:calendarDate(item.date,now)});
  }
  return result;
}
export function mergeScores(kev, scores, previous, now = new Date()) {
  if (!kev) return null;
  const old = new Map((previous?.latest || []).map(item=>[item.cve,item]));
  return {...kev,latest:kev.latest.map(item=>{
    const current=scores?.get(item.cve);
    if(current)return {...item,...current};
    const prior=old.get(item.cve);
    if(prior?.scoreDate && Number.isFinite(prior.epss) && prior.epss>=0 && prior.epss<=1 && Number.isFinite(prior.percentile) && prior.percentile>=0 && prior.percentile<=1){
      try { calendarDate(prior.scoreDate,now);return {...item,epss:prior.epss,percentile:prior.percentile,scoreDate:prior.scoreDate}; } catch { /* An invalid old score is not retained. */ }
    }
    return item;
  })};
}

export async function requestSource(url, {fetchImpl=fetch,maxBytes=8_000_000,timeoutMs=20_000,retries=1}={}) {
  const initial=safeUrl(url);
  let finalError;
  for(let attempt=0;attempt<=retries;attempt++){
    const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),timeoutMs);
    let retryable=true,retryDelay=0;
    try {
      let current=initial,response;
      for(let redirect=0;redirect<5;redirect++){
        const headers={'User-Agent':'Cyberonik-Risk-Monitor/1.0 (+https://cyberonik-website.vercel.app/cyber-risk)','Accept':'application/json, application/rss+xml, application/xml, text/html, application/pdf;q=0.9, */*;q=0.5'};
        response=await fetchImpl(current,{redirect:'manual',signal:controller.signal,headers});
        if([301,302,303,307,308].includes(response.status)){
          const location=response.headers.get('location');
          await response.body?.cancel();
          if(!location)throw new Error('Source redirect has no destination');
          current=safeUrl(new URL(location,current).href);
          if(redirect===4)throw new Error('Too many source redirects');
          continue;
        }
        break;
      }
      if(!response?.ok){
        if(response?.status>=400&&response.status<500&&![408,429].includes(response.status))retryable=false;
        if(response?.status===429){
          const retryAfter=response.headers.get('retry-after');
          const delay=retryAfter&&/^\d+$/.test(retryAfter)?Number(retryAfter)*1000:Date.parse(retryAfter||'')-Date.now();
          if(Number.isFinite(delay)&&delay>0){if(delay>5000)retryable=false;else retryDelay=delay;}
        }
        await response?.body?.cancel();
        throw new Error('Source request failed with HTTP '+(response?.status || 'unknown'));
      }
      if(Number(response.headers.get('content-length'))>maxBytes)throw new Error('Source exceeds size limit');
      if(!response.body)throw new Error('Source response has no body');
      const reader=response.body.getReader(),chunks=[];let size=0;
      while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();throw new Error('Source exceeds size limit');}chunks.push(value);}
      if(!size)throw new Error('Empty source response');
      const bytes=Buffer.concat(chunks);
      return {bytes,text:bytes.toString('utf8'),url:current,contentType:response.headers.get('content-type') || ''};
    } catch(error){finalError=error instanceof Error?error:new Error('Source request failed');if(!retryable)break;}
    finally{clearTimeout(timer);}
    if(retryDelay&&attempt<retries)await new Promise(resolve=>setTimeout(resolve,retryDelay));
  }
  throw finalError;
}
function sourceStatus(key,now,prior,{ok,url,dataDate,message}){
  return {name:names[key],url:url||feedUrls[key]||prior?.url||'https://www.ibm.com/reports/data-breach',status:ok?'ok':'error',lastAttemptAt:now.toISOString(),lastSuccessAt:ok?now.toISOString():prior?.lastSuccessAt||null,...((dataDate||prior?.dataDate)?{dataDate:dataDate||prior?.dataDate}:{}),...(message?{message}:{} )};
}
function failureMessage(error){return error instanceof Error?error.message.slice(0,240):'Source check failed';}
export function verifyBenchmark(config, response){
  if(config.verification?.kind==='sha256'){
    if(!/^[a-f0-9]{64}$/i.test(config.verification.hash||''))throw new Error('Missing benchmark document hash');
    return createHash('sha256').update(response.bytes).digest('hex')===config.verification.hash.toLowerCase();
  }
  const anchors=config.anchors||config.verification?.anchors;
  if(!Array.isArray(anchors)||!anchors.length||anchors.some(anchor=>typeof anchor!=='string'||!anchor.trim())||(anchors.length===1&&anchors[0].trim().length<12))throw new Error('Benchmark requires meaningful evidence anchors');
  const content=plainText(response.text).normalize('NFKC').toLowerCase();
  return anchors.every(anchor=>content.includes(plainText(anchor).normalize('NFKC').toLowerCase()));
}
export async function collectSnapshot({previous=null,config,now=new Date(),request=requestSource}){
  if(!config || !Array.isArray(config.benchmarks) || !config.benchmarks.length)throw new Error('Missing curated benchmark configuration');
  const sources={}, prior=previous?.schemaVersion===1?previous:null;
  let kev=prior?.kev||null,alerts=prior?.alerts||[],scores=null;
  const kevTask=(async()=>{
    let primaryError;
    for(const url of [feedUrls.kev,feedUrls.kevFallback]){
      try{
        const response=await request(url,{maxBytes:16_000_000});
        const parsed=parseKev(response.text,now);
        if(prior?.kev?.total && parsed.total<prior.kev.total*0.8)throw new Error('KEV catalogue unexpectedly shrank; review required');
        if(prior?.kev?.dateReleased && parsed.dateReleased<prior.kev.dateReleased)throw new Error('KEV catalogue regressed; review required');
        kev=parsed;sources.kev=sourceStatus('kev',now,prior?.sources?.kev,{ok:true,url:response.url||url,dataDate:parsed.dateReleased,message:url===feedUrls.kevFallback?'Official CISA GitHub mirror used after the primary feed was unavailable.':undefined});return;
      }catch(error){primaryError=error;}
    }
    sources.kev=sourceStatus('kev',now,prior?.sources?.kev,{ok:false,message:failureMessage(primaryError)});
  })();
  const alertsTask=(async()=>{
    try{const response=await request(feedUrls.alerts,{maxBytes:2_000_000});alerts=parseAlerts(response.text,now);sources.alerts=sourceStatus('alerts',now,prior?.sources?.alerts,{ok:true,dataDate:alerts[0].publishedAt});}
    catch(error){sources.alerts=sourceStatus('alerts',now,prior?.sources?.alerts,{ok:false,message:failureMessage(error)});}
  })();
  const benchmarkTask=(async()=>{
    const requests=new Map();
    const seen=new Set();
    const benchmarks=await Promise.all(config.benchmarks.map(async item=>{
      const id=text(item.id,'benchmark ID',100);
      if(seen.has(id))throw new Error('Duplicate benchmark configuration');seen.add(id);
      const sourceUrl=safeUrl(item.sourceUrl);
      const current={id,value:text(item.value,'benchmark value',120),label:text(item.label,'benchmark label',300),description:text(item.description,'benchmark description',4000),sourceName:text(item.sourceName,'benchmark source',200),sourceUrl,period:text(item.period,'benchmark period',500)};
      const old=prior?.benchmarks?.find(value=>value.id===id&&value.value===current.value&&value.sourceUrl===current.sourceUrl&&value.period===current.period);
      const checkedAt=old?.checkedAt||null;
      try{
        if(!requests.has(sourceUrl))requests.set(sourceUrl,request(sourceUrl,{maxBytes:20_000_000}));
        const response=await requests.get(sourceUrl);
        const matches=verifyBenchmark(item,response);
        return {...current,checkedAt:matches?now.toISOString():checkedAt,status:matches?'verified':'review-required'};
      }catch{return {...current,checkedAt,status:checkedAt?'review-required':'unavailable'};}
    }));
    const discoveryFailures=[];
    for(const discovery of config.releaseDiscovery||[]){
      try{
        const sourceUrl=safeUrl(discovery.sourceUrl);
        if(!Number.isInteger(discovery.currentReportYear)||discovery.currentReportYear<2000||typeof discovery.linkPattern!=='string'||discovery.linkPattern.length>250)throw new Error('Invalid release-discovery configuration');
        const response=await request(sourceUrl,{maxBytes:2_000_000});
        const matches=[...response.text.matchAll(new RegExp(discovery.linkPattern,'g'))];
        if(!matches.length)throw new Error('Annual-report index no longer matches its expected links');
        const latestYear=Math.max(...matches.map(match=>Number(match[1])).filter(year=>Number.isInteger(year)&&year>=2000&&year<=now.getUTCFullYear()));
        if(latestYear>discovery.currentReportYear){
          for(const item of benchmarks.filter(item=>new URL(item.sourceUrl).hostname===new URL(sourceUrl).hostname)){item.status='review-required';item.checkedAt=prior?.benchmarks?.find(old=>old.id===item.id)?.checkedAt||null;}
          discoveryFailures.push('A newer annual report is available; figures need review before replacement.');
        }
      }catch(error){discoveryFailures.push('Annual-report discovery: '+failureMessage(error));}
    }
    const count=benchmarks.filter(item=>item.status!=='verified').length;
    sources.benchmarks=sourceStatus('benchmarks',now,prior?.sources?.benchmarks,{ok:count===0&&discoveryFailures.length===0,url:benchmarks[0]?.sourceUrl,message:discoveryFailures.length?discoveryFailures.join(' '):count?`${count} benchmark source check(s) require review or are unavailable. Values retain their curated publication periods.`:'Source checks confirm the curated figures or unchanged source documents; they do not create new research observations.'});
    return benchmarks;
  })();
  await kevTask;
  try{
    if(!kev?.latest?.length)throw new Error('No validated KEV entries available for EPSS');
    const requested=kev.latest.map(item=>item.cve);
    const response=await request(feedUrls.epss+'?cve='+encodeURIComponent(requested.join(',')),{maxBytes:1_000_000});
    scores=parseEpss(response.text,requested,now);
    const dates=[...scores.values()].map(item=>item.scoreDate).sort();
    sources.epss=sourceStatus('epss',now,prior?.sources?.epss,{ok:true,dataDate:dates.at(-1),message:scores.size<requested.length?'Scores are available for '+scores.size+' of '+requested.length+' displayed CVEs. Existing unmatched scores retain their own dates.':undefined});
  }catch(error){sources.epss=sourceStatus('epss',now,prior?.sources?.epss,{ok:false,message:failureMessage(error)});}
  await alertsTask;
  const benchmarks=await benchmarkTask;
  kev=mergeScores(kev,scores,prior?.kev,now);
  return {schemaVersion:1,generatedAt:now.toISOString(),sources,kev,alerts,benchmarks};
}
