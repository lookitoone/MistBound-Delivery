// Authenticated packages; the shared secret remains in the URL fragment.
const utf8=new TextEncoder();
const fail=()=>{throw Error('공유 링크 또는 배포 파일 검증에 실패했습니다.');};
export function keyBytes(text){if(!/^[A-Za-z0-9_-]{43}$/.test(text||''))return fail();return from64(text);}
function from64(text){try{return Uint8Array.from(atob(text.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((-text.length>>>0)%4)),c=>c.charCodeAt(0));}catch{return fail();}}
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
async function hmac(key,bytes){const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);return new Uint8Array(await crypto.subtle.sign('HMAC',k,bytes));}
export async function digest(bytes){return hex(await crypto.subtle.digest('SHA-256',bytes));}
export async function metadata(envelope,key){
 if(envelope?.schema!==1||typeof envelope.payload!=='string'||envelope.payload.length>65536||!/^[a-f0-9]{64}$/.test(envelope.signature||''))return fail();
 const body=from64(envelope.payload),secret=await hmac(key,utf8.encode('MistBound manifest v1'));
 const k=await crypto.subtle.importKey('raw',secret,{name:'HMAC',hash:'SHA-256'},false,['verify']);
 const tag=Uint8Array.from(envelope.signature.match(/../g),x=>parseInt(x,16));
 if(!await crypto.subtle.verify('HMAC',k,tag,body))return fail();
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));
}
export async function decryptPackage(bytes,key){
 // Reuse a view instead of copying the entire ~190MB installer.
 const data=ArrayBuffer.isView(bytes)?new Uint8Array(bytes.buffer,bytes.byteOffset,bytes.byteLength):new Uint8Array(bytes);if(data.length<88||data.length%16!==8||new TextDecoder().decode(data.subarray(0,8))!=='MBLINK01')return fail();
 const source=await crypto.subtle.importKey('raw',key,'HKDF',false,['deriveBits']);
 const derived=new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:data.subarray(8,24),info:utf8.encode('MistBound shared link package v1')},source,512));
 const tagKey=await crypto.subtle.importKey('raw',derived.subarray(32),{name:'HMAC',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('HMAC',tagKey,data.subarray(data.length-32),data.subarray(0,data.length-32)))return fail();
 const cipherKey=await crypto.subtle.importKey('raw',derived.subarray(0,32),'AES-CBC',false,['decrypt']);
 try{return await crypto.subtle.decrypt({name:'AES-CBC',iv:data.subarray(24,40)},cipherKey,data.subarray(40,data.length-32));}catch{return fail();}
}
