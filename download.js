import {keyBytes,metadata,decryptPackage,digest} from './crypto.mjs';
const button=document.querySelector('#download'),status=document.querySelector('#status'),bar=document.querySelector('#progress');
let save=document.querySelector('#save');
if(!save){save=document.createElement('a');save.id='save';save.className='save';save.hidden=true;button.after(save);}
let key,release,preparedURL;
const messages={
 missing:'공유 주소의 뒷부분이 빠졌습니다. 전달받은 링크 전체를 복사해 주소창에서 열어 주세요.',
 key:'공유 주소의 뒷부분이 잘렸거나 바뀌었습니다. 전달받은 링크 전체를 다시 열어 주세요.',
 browser:'이 브라우저에서 파일 검증 기능을 사용할 수 없습니다. 최신 Chrome 또는 삼성 인터넷에서 HTTPS 주소로 열어 주세요.',
 network:'배포 서버에 연결하지 못했습니다. Wi-Fi/모바일 데이터 연결을 바꿔 보거나 아래 버튼으로 다시 확인해 주세요.',
 response:'배포 정보를 정상적으로 받지 못했습니다. 아래 버튼으로 다시 확인해 주세요.',
 auth:'링크와 배포 정보의 서명이 일치하지 않습니다. 전달받은 원본 링크 전체로 다시 열어 주세요.',
 format:'배포 파일 정보에 문제가 있습니다. 잠시 후 다시 확인해 주세요.'
};
function problem(code){const e=new Error(messages[code]);e.code=code;return e;}
function validFile(file){return file&&Number.isSafeInteger(file.size)&&file.size>0&&file.size<350*1024*1024&&/^[a-f0-9]{64}$/.test(file.sha256||'');}
function clearPrepared(){if(preparedURL)URL.revokeObjectURL(preparedURL);preparedURL=null;save.hidden=true;save.removeAttribute('href');}
function error(message){status.textContent=message;button.hidden=false;button.textContent=release?'다운로드 다시 시도':'배포 정보 다시 확인';button.disabled=false;bar.hidden=true;}
async function envelope(){
 // The shared key is never included in either request or its referrer.
 const stamp=Date.now();let last='network';
 for(const url of [`./latest.json?t=${stamp}`,`https://raw.githubusercontent.com/lookitoone/MistBound-Delivery/main/latest.json?t=${stamp}`]){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
  try{
   const response=await fetch(url,{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',signal:controller.signal});
   if(!response.ok){last='network';continue;}
   const text=await response.text();if(text.length>65536){last='response';continue;}
   try{return JSON.parse(text);}catch{last='response';}
  }catch{last='network';}finally{clearTimeout(timer);}
 }
 throw problem(last);
}
async function init(){
 release=null;button.disabled=true;button.hidden=false;button.textContent='배포 정보 확인 중';bar.hidden=true;
 document.querySelector('#version').textContent='연결 확인 중';status.textContent='배포 정보를 확인하고 있습니다.';
 try{
  const raw=new URLSearchParams(location.hash.slice(1)).get('k');
  if(!raw)throw problem('missing');
  if(!/^[A-Za-z0-9_-]{43}$/.test(raw.trim()))throw problem('key');
  key=keyBytes(raw.trim());
  if(!globalThis.crypto?.subtle||globalThis.isSecureContext===false)throw problem('browser');
  const signed=await envelope();let data;
  try{data=await metadata(signed,key);}catch(e){throw problem(e.name==='NotSupportedError'?'browser':'auth');}
  const file=data?.installer;
  if(data?.schema!==1||!/^\d+\.\d+\.\d+$/.test(data.version)||!validFile(file)||!validFile({size:file.encrypted_size,sha256:file.encrypted_sha256})||!Array.isArray(file.parts)||!file.parts.length||file.parts.length>64)throw problem('format');
  let total=0;for(const part of file.parts){if(!validFile(part)||!/^v[0-9.]+-installer-\d{3}\.mbpart$/.test(part.file))throw problem('format');total+=part.size;}
  if(total!==file.encrypted_size)throw problem('format');
  release=data;document.querySelector('#version').textContent='v'+data.version;button.textContent='Windows용 파일 준비';button.disabled=false;status.textContent='로그인 없이 받을 수 있습니다. 파일 준비 후 ‘설치 파일 저장’을 눌러 주세요.';
 }catch(e){error(e.message||messages.response);}
}
button.addEventListener('click',async()=>{
 if(!release){await init();return;}
 button.disabled=true;bar.hidden=false;bar.value=0;clearPrepared();const file=release.installer;
 try{
  let bytes=new Uint8Array(file.encrypted_size);let done=0;
  for(const part of file.parts){
   const response=await fetch('./'+part.file,{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
   if(!response.ok)throw Error('설치 파일 연결이 끊겼습니다. 다운로드를 다시 시도해 주세요.');
   let count=0;const start=done;
   function append(value){if(count+value.length>part.size)throw Error('파일 크기 검증 실패');bytes.set(value,done);count+=value.length;done+=value.length;bar.value=done/file.encrypted_size*90;status.textContent=`파일 준비 중 · ${Math.floor(done/file.encrypted_size*100)}%`;}
   if(response.body?.getReader){
    const reader=response.body.getReader();
    try{while(true){const {value,done:ended}=await reader.read();if(ended)break;append(value);}}
    catch(e){try{await reader.cancel();}catch{}throw e;}
    finally{reader.releaseLock();}
   }else{append(new Uint8Array(await response.arrayBuffer()));}
   if(count!==part.size||await digest(bytes.subarray(start,done))!==part.sha256)throw Error('내려받은 파일이 손상됐습니다. 다시 시도해 주세요.');
  }
  status.textContent='설치 파일 검증 중…';if(await digest(bytes)!==file.encrypted_sha256)throw Error('파일 검증 실패');
  const plain=await decryptPackage(bytes,key);bytes=null;
  if(plain.byteLength!==file.size||await digest(plain)!==file.sha256)throw Error('설치 파일 검증 실패');
  preparedURL=URL.createObjectURL(new Blob([plain],{type:'application/octet-stream'}));
  save.href=preparedURL;save.download='MistBound-AI.exe';save.textContent='설치 파일 저장';save.hidden=false;button.hidden=true;
  bar.value=100;status.textContent='파일 준비가 끝났습니다. ‘설치 파일 저장’을 눌러 브라우저에 저장해 주세요. 휴대폰에서는 보관·PC 전달만 가능하며 실행은 Windows PC에서 합니다.';
 }catch(e){error(e.message||'파일을 준비하지 못했습니다. 브라우저를 닫았다 다시 열거나 Windows PC에서 시도해 주세요.');}
});
save.addEventListener('click',()=>{status.textContent='브라우저에 저장을 요청했습니다. 다운로드 목록을 확인해 주세요. 저장되지 않았다면 ‘설치 파일 저장’을 다시 눌러 주세요.';});
init();
