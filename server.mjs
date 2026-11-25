import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {randomBytes,createHash,createCipheriv,createDecipheriv,scrypt,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
const derive=promisify(scrypt);
const base=path.dirname(fileURLToPath(import.meta.url));
const env=process.env,dir=env.DATA_DIR||'/var/data',port=Number(env.PORT||10000);
if(!env.DATA_KEY || env.DATA_KEY.length<32)throw Error('DATA_KEY must contain at least 32 characters');
const key=createHash('sha256').update(env.DATA_KEY).digest();
const hash=x=>createHash('sha256').update(x).digest('hex');
function seal(data){
  const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',key,iv);
  const bytes=Buffer.concat([c.update(JSON.stringify(data),'utf8'),c.final()]);
  return Buffer.concat([iv,c.getAuthTag(),bytes]);
}
function open(body){
  const b=Buffer.from(body),c=createDecipheriv('aes-256-gcm',key,b.subarray(0,12));c.setAuthTag(b.subarray(12,28));
  return JSON.parse(Buffer.concat([c.update(b.subarray(28)),c.final()]).toString('utf8'));
}
fs.mkdirSync(dir,{recursive:true});
const db=new DatabaseSync(path.join(dir,'workdesk.sqlite'));
db.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS users (login TEXT PRIMARY KEY, role TEXT NOT NULL, salt TEXT NOT NULL, password TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1); CREATE TABLE IF NOT EXISTS session (token TEXT PRIMARY KEY, login TEXT REFERENCES users(login), expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS workspace (id INTEGER PRIMARY KEY CHECK(id=1), rev INTEGER NOT NULL, body BLOB, previous BLOB); INSERT OR IGNORE INTO workspace VALUES(1,0,NULL,NULL)");
const q=sql=>db.prepare(sql);
function fail(code,msg){throw Object.assign(new Error(msg),{code});}
const roles=['팀장','사무실 직원','현장관리자','통역'];
const full=r=>roles.slice(0,2).includes(r);
function credentials(login,pw){
 if(typeof login!=='string'||!login.trim()||login.length>80||typeof pw!=='string'||pw.length<12||pw.length>256)fail(400,'아이디와 12~256자 비밀번호를 확인하세요.');
}
async function password(pw,salt){return Buffer.from(await derive(pw,salt,32,{N:32768,r:8,p:1,maxmem:67108864}));}
async function create(login,pw,role){
 credentials(login,pw);if(!roles.includes(role))fail(400,'역할을 확인하세요.');
 const salt=randomBytes(16).toString('base64'),digest=(await password(pw,salt)).toString('hex');
 if(!q('INSERT OR IGNORE INTO users(login,role,salt,password) VALUES(?,?,?,?)').run(login.trim(),role,salt,digest).changes)fail(409,'이미 등록된 아이디입니다.');
}
if(!q('SELECT login FROM users LIMIT 1').get())await create(env.ADMIN_LOGIN,env.ADMIN_PASSWORD,roles[0]);
if(q('SELECT body FROM workspace WHERE id=1').get().body)open(q('SELECT body FROM workspace WHERE id=1').get().body);
const files=Object.fromEntries(['login','office','attendance','accounts'].map(n=>[n,fs.readFileSync(path.join(base,n+'.html'))]));
const noAuth='로그인이 필요합니다.';
const cookieName='__Host-ezdesk';
const cookie=(value,secs)=>cookieName+'='+value+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age='+secs;
const durations=new Map();let hashing=0;
function limit(id,max){
 const now=Date.now();let item=durations.get(id);if(!item||item.until<now){item={n:0,until:now+600000};durations.set(id,item);}
 if(++item.n>max)fail(429,'잠시 후 다시 시도하세요.');
}
setInterval(()=>{for(const [id,item] of durations)if(item.until<Date.now())durations.delete(id);q('DELETE FROM session WHERE expires<?').run(Date.now());},60000).unref();
function attendance(data,date){
 if(!data)return [];
 const days=new Map(data.days.filter(d=>d.date===date).map(d=>[d.emp,d]));
 const dow=String(new Date(date+'T12:00:00Z').getUTCDay());
 return data.staff.flatMap(e=>{
   const d=days.get(e.id);
   if(!d && !(e.hire<=date&&(!e.exit||date<=e.exit)&&String(e.week||'').includes(dow)))return [];
   const assignment=(e.assignments||[]).filter(a=>a.from<=date).sort((a,b)=>b.from.localeCompare(a.from))[0];
   const row={name:e.name,group:d?.group||assignment?.group||e.firstGroup||e.group||'',state:!d?'미확인':d.absent?'결근':'출근'};
   if(d&&!d.absent)for(const k of ['start','end','bs','be','arrive','leave','ot'])row[k]=d[k];
   return [row];
 });
}
const arrays=['staff','days','charges','credits','receipts','bonuses','locks','operating','rooms','fleet','boardings','groups'];
async function payload(req,limitBytes){
 if(!req.headers['content-type']?.startsWith('application/json'))fail(415,'JSON 요청을 확인하세요.');
 let size=0;const parts=[];for await(const part of req){size+=part.length;if(size>limitBytes)fail(413,'입력 자료가 너무 큽니다.');parts.push(part);}
 try{const b=JSON.parse(Buffer.concat(parts));if(!b||Array.isArray(b)||typeof b!=='object')throw Error();return b;}catch{fail(400,'입력 내용을 확인하세요.');}
}
const server=http.createServer(async(req,res)=>{
 const json=(value,status=200)=>{res.writeHead(status,{'Content-Type':'application/json;charset=utf-8'});res.end(JSON.stringify(value));};
 const page=n=>{res.writeHead(200,{'Content-Type':'text/html;charset=utf-8'});res.end(files[n]);};
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
 res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
 try{
 const u=new URL(req.url,'http://local'),p=u.pathname,m=req.method;
 if(p==='/health'&&m==='GET')return json({ok:true});
 const token=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(cookieName+'='))?.slice(cookieName.length+1)||'';
 const user=q('SELECT u.login,u.role,u.salt FROM session s JOIN users u ON s.login=u.login WHERE s.token=? AND s.expires>? AND u.enabled=1').get(hash(token),Date.now());
 if(m!=='GET'){
   if(req.headers.origin!=='https://'+req.headers.host)fail(403,'접속 주소를 확인하세요.');
 }
 if(p==='/api/login'&&m==='POST'){
   const {login,pw}=await payload(req,4096);if(typeof login!=='string'||typeof pw!=='string'||pw.length>256||login.length>80)fail(401,'아이디 또는 비밀번호를 확인하세요.');
   const id=login.trim(),u=q('SELECT * FROM users WHERE login=? AND enabled=1').get(id);
   limit('total',400);if(u)limit('login-'+u.login,18);if(hashing>=4)fail(429,'잠시 후 다시 시도하세요.');
   hashing++;let attempt;try{attempt=await password(pw,u?.salt||'unregistered-account');}finally{hashing--;}
   if(!u||!timingSafeEqual(attempt,Buffer.from(u.password,'hex')))fail(401,'아이디 또는 비밀번호를 확인하세요.');
   if(!q('SELECT login FROM users WHERE login=? AND password=? AND enabled=1').get(id,u.password))fail(401,noAuth);
   durations.delete('login-'+id);
   const session=randomBytes(32).toString('hex');q('INSERT INTO session VALUES(?,?,?)').run(hash(session),id,Date.now()+8*3600000);res.setHeader('Set-Cookie',cookie(session,28800));return json({ok:true});
 }
 if(p==='/'&&m==='GET')return page(!user?'login':full(user.role)?'office':'attendance');
 if(!user)fail(401,noAuth);
 if(p==='/api/logout'&&m==='POST'){q('DELETE FROM session WHERE token=?').run(hash(token));res.setHeader('Set-Cookie',cookie('',0));return json({ok:true});}
 if(p==='/api/attendance'&&m==='GET'){
  const date=u.searchParams.get('day');if(!/^\d{4}-\d\d-\d\d$/.test(date||''))fail(400,'조회일을 확인하세요.');
  const {body}=q('SELECT body FROM workspace WHERE id=1').get();return json(attendance(body?open(body):null,date));
 }
 if(!full(user.role))fail(403,'근태 조회 전용 계정입니다.');
 if(p==='/accounts'&&m==='GET')return page('accounts');
 if(p==='/api/users'&&m==='GET')return json(q('SELECT login,role,enabled FROM users ORDER BY login').all());
 if(p==='/api/users'&&m==='POST'){
  const f=await payload(req,4096);await create(f.login,f.pw,f.role);return json({ok:true},201);
 }
 if(p==='/api/user-settings'&&m==='POST'){
  const {login,role,enabled,pw}=await payload(req,4096);
  if(login===user.login||!q('SELECT login FROM users WHERE login=?').get(login)||!roles.includes(role)||typeof enabled!=='boolean')fail(400,'다른 직원 계정과 역할을 선택하세요.');
  let salt,digest;if(pw){credentials(login,pw);salt=randomBytes(16).toString('base64');digest=(await password(pw,salt)).toString('hex');}
  db.exec('BEGIN IMMEDIATE');try{q('UPDATE users SET role=?,enabled=?,salt=coalesce(?,salt),password=coalesce(?,password) WHERE login=?').run(role,+enabled,salt??null,digest??null,login);
   q('DELETE FROM session WHERE login=?').run(login);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}return json({ok:true});
 }
 if(p==='/api/workspace'&&m==='GET'){
  const r=q('SELECT rev,body FROM workspace WHERE id=1').get();return json({rev:r.rev,data:r.body?open(r.body):null,login:user.login,role:user.role,backupSalt:user.salt});
 }
 if(p==='/api/workspace'&&m==='PUT'){
  const {rev,data}=await payload(req,16*1024*1024);if(!Number.isSafeInteger(rev)||!data||!arrays.every(k=>Array.isArray(data[k])))fail(400,'자료 형식을 확인하세요.');
  if(!q('SELECT u.login FROM session s JOIN users u ON u.login=s.login WHERE s.token=? AND s.expires>? AND u.enabled=1 AND u.role IN (?,?)').get(hash(token),Date.now(),...roles.slice(0,2)))fail(403,noAuth);
  if(!q('UPDATE workspace SET previous=body,body=?,rev=rev+1 WHERE id=1 AND rev=?').run(seal(data),rev).changes)fail(409,'다른 직원이 먼저 저장했습니다. 새로고침한 후 다시 입력하세요.');
  return json({rev:rev+1});
 }
 fail(404,'요청을 확인하세요.');
 }catch(e){if(!res.headersSent)json({error:Number.isInteger(e.code)?e.message:'서버 처리 중 오류가 발생했습니다.'},Number.isInteger(e.code)?e.code:500);else res.end();}
});
server.listen(port,'0.0.0.0',()=>console.log('EasySolution ready'));

