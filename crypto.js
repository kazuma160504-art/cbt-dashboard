// CBTダッシュボード 共通暗号処理（AES-GCM / PBKDF2）
// パスコードから鍵を導出し、成績データを暗号化/復号する。
// 暗号化されたデータ(data.enc.js)は公開されても、パスコードなしでは中身は読めない。
async function _cbtKey(pass, salt){
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:150000, hash:'SHA-256' },
    km, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
const _b64  = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const _ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function cbtEncrypt(obj, pass){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await _cbtKey(pass, salt);
  const ct   = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { v:1, salt:_b64(salt), iv:_b64(iv), ct:_b64(ct) };
}
async function cbtDecrypt(blob, pass){
  const key = await _cbtKey(pass, _ub64(blob.salt));
  const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv:_ub64(blob.iv) }, key, _ub64(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
