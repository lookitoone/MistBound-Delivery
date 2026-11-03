import {keyBytes,metadata,decryptPackage,digest} from './crypto.mjs';
const button=document.querySelector('#download'),status=document.querySelector('#status'),bar=document.querySelector('#progress');
let key,release;
function validFile(file){return file&&Number.isSafeInteger(file.size)&&file.size>0&&file.size<350*1024*1024&&/^[a-f0-9]{64}$/.test(file.sha256||'');}
function error(message){status.textContent=message;button.textContent='다시 다운로드';button.disabled=!release;bar.hidden=true;}
async function init(){try{
 key=keyBytes(new URLSearchParams(location.hash.slice(1)).get('k'));
 const response=await fetch('./latest.json',{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
 if(!response.ok)throw Error('배포 정보를 불러오지 못했습니다. 잠시 후 다시 접속해 주세요.');
 const envelope=await response.text();if(envelope.length>65536)throw Error('배포 정보 크기 오류');
 const data=await metadata(JSON.parse(envelope),key),file=data.installer;
 if(data.schema!==1||!/^\d+\.\d+\.\d+$/.test(data.version)||!validFile(file)||!validFile({size:file.encrypted_size,sha256:file.encrypted_sha256})||!Array.isArray(file.parts)||!file.parts.length||file.parts.length>32)throw Error('배포 파일 정보 오류');
 let total=0;for(const part of file.parts){if(!validFile(part)||!/^v[0-9.]+-installer-\d{3}\.mbpart$/.test(part.file))throw Error('배포 파일 경로 오류');total+=part.size;}
 if(total!==file.encrypted_size)throw Error('배포 파일 크기 오류');
 release=data;document.querySelector('#version').textContent='v'+data.version;button.textContent='Windows용 다운로드';button.disabled=false;status.textContent='로그인 없이 다운로드할 수 있습니다.';
 }catch{error(location.hash?'링크를 확인하지 못했습니다. 전달받은 링크 전체로 다시 접속해 주세요.':'전달받은 링크 전체로 접속해 주세요.');}}
button.addEventListener('click',async()=>{if(!release)return;button.disabled=true;bar.hidden=false;bar.value=0;const file=release.installer;try{
 const bytes=new Uint8Array(file.encrypted_size);let done=0;
 for(const part of file.parts){const response=await fetch('./'+part.file,{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});if(!response.ok||!response.body)throw Error('다운로드 연결을 확인해 주세요.');
 const reader=response.body.getReader();let count=0;const start=done;
 while(true){const {value,done:ended}=await reader.read();if(ended)break;if(count+value.length>part.size){await reader.cancel();throw Error('파일 크기 검증 실패');}bytes.set(value,done);count+=value.length;done+=value.length;bar.value=done/file.encrypted_size*90;status.textContent=`다운로드 중 · ${Math.floor(done/file.encrypted_size*100)}%`;}
 if(count!==part.size||await digest(bytes.subarray(start,done))!==part.sha256)throw Error('내려받은 파일이 손상됐습니다. 다시 시도해 주세요.');}
 status.textContent='설치 파일 검증 중…';if(await digest(bytes)!==file.encrypted_sha256)throw Error('파일 검증 실패');
 const plain=await decryptPackage(bytes,key);if(plain.byteLength!==file.size||await digest(plain)!==file.sha256)throw Error('설치 파일 검증 실패');
 const url=URL.createObjectURL(new Blob([plain],{type:'application/octet-stream'}));const a=document.createElement('a');a.href=url;a.download='MistBound-AI.exe';a.click();setTimeout(()=>URL.revokeObjectURL(url),60000);
 bar.value=100;status.textContent='다운로드가 준비됐습니다. MistBound-AI.exe를 실행해 주세요.';button.textContent='다시 다운로드';button.disabled=false;
 }catch(e){error(e.message||'다운로드하지 못했습니다. 잠시 후 다시 시도해 주세요.');}});
init();
