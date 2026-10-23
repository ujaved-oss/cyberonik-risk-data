import {readFile,writeFile,mkdir,rename} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {collectSnapshot} from './core.mjs';

const directory=dirname(fileURLToPath(import.meta.url));
const args=process.argv.slice(2),options={};
for(let index=0;index<args.length;index+=2){
  if(!['--previous','--output','--config'].includes(args[index])||!args[index+1]||args[index+1].startsWith('--'))throw new Error('Usage: node collect.mjs --previous snapshot.json --output snapshot.json [--config benchmarks.json]');
  options[args[index].slice(2)]=resolve(args[index+1]);
}
if(!options.output)throw new Error('--output is required');
const config=JSON.parse(await readFile(options.config||resolve(directory,'benchmarks.json'),'utf8'));
let previous=null;
if(options.previous){
  try{previous=JSON.parse(await readFile(options.previous,'utf8'));if(previous?.schemaVersion!==1||!previous.sources||!Array.isArray(previous.benchmarks)||!Array.isArray(previous.alerts))throw new Error('Previous snapshot has an unsupported shape');}
  catch(error){if(error.code!=='ENOENT')throw error;}
}
const snapshot=await collectSnapshot({previous,config});
await mkdir(dirname(options.output),{recursive:true});
const temporary=options.output+'.tmp-'+process.pid;
await writeFile(temporary,JSON.stringify(snapshot,null,2)+'\n','utf8');
await rename(temporary,options.output);
const failed=Object.entries(snapshot.sources).filter(([,source])=>source.status==='error');
console.log(JSON.stringify({generatedAt:snapshot.generatedAt,output:options.output,kevEntries:snapshot.kev?.total??null,advisories:snapshot.alerts.length,benchmarks:snapshot.benchmarks.length,sources:Object.fromEntries(Object.entries(snapshot.sources).map(([key,source])=>[key,{status:source.status,lastSuccessAt:source.lastSuccessAt,message:source.message}]))},null,2));
if(failed.length)process.exitCode=1;
